#!/usr/bin/env python
"""
Disaster-recovery drill (NOC-027): backup -> destroy -> restore -> verify,
against a fully isolated, throwaway compose project -- never the real
hp_prod_data/hp_prod_myapp volumes.

Demonstrates that backup_sqlite.sh's backups (NOC-026) actually allow
returning to operation, not just that they're produced without error:
writes a known marker into the live DB and into /var/lib/myapp, backs
both up (same operations backup_sqlite.sh performs: sqlite3 .backup, tar,
then scripts/backup_tool.py encrypt), genuinely destroys the volumes (not
just stops the containers -- `docker compose down -v`), restores from the
backup into fresh volumes (same operations restore_backup.sh performs),
brings the stack back up, and verifies the marker survived byte-for-byte,
the schema's Alembic migration state is intact, and the app serves
/health again.

Reports measured RTO (wall-clock time for the destroy -> restored ->
serving-again cycle) and RPO (the gap between the last backup and the
simulated loss -- near-zero in a drill by construction, since restore
happens immediately after backup; a real deployment's RPO is bounded by
backup cadence instead -- see documentation/ops/vps/DEPLOY.md's §11b,
daily at 02:15 UTC, so worst case up to ~24h of data since the last
successful run).

Exits non-zero on any failed verification. Always tears down its own
throwaway project+volumes on exit, success or failure, unless --keep is
passed (useful for inspecting a failure).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_COMPOSE_FILE = _REPO_ROOT / "compose" / "docker-compose.prod.yml"


class DrillFailed(Exception):
    pass


def _run(cmd: List[str], *, env: Optional[dict] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(_REPO_ROOT), env=env, capture_output=True, text=True, timeout=timeout)


def _run_ok(cmd: List[str], *, env: Optional[dict] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    result = _run(cmd, env=env, timeout=timeout)
    if result.returncode != 0:
        raise DrillFailed(f"command failed ({result.returncode}): {' '.join(cmd)}\nstderr: {result.stderr}")
    return result


class Drill:
    def __init__(self, env_file: Path, project: str, keep: bool, verbose: bool):
        self.env_file = env_file
        self.project = project
        self.keep = keep
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["COMPOSE_PROJECT_NAME"] = project

    def log(self, msg: str) -> None:
        print(f"[dr-drill] {msg}", file=sys.stderr)

    def compose(self, args: List[str], **kwargs) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-f", str(_COMPOSE_FILE), "--env-file", str(self.env_file)] + args
        return _run_ok(cmd, env=self.env, **kwargs)

    def config(self) -> dict:
        return json.loads(self.compose(["config", "--format", "json"]).stdout)

    def resolved(self) -> dict:
        cfg = self.config()
        return {
            "data_volume": cfg["volumes"]["hp_prod_data"]["name"],
            "myapp_volume": cfg["volumes"]["hp_prod_myapp"]["name"],
            "app_image": cfg["services"]["app"]["image"],
        }

    def up(self) -> None:
        self.compose(["up", "-d", "migrate", "app", "admin"], timeout=180)

    def wait_healthy(self, timeout: int = 60) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = _run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", f"{self.project}-app-1"],
                env=self.env,
            )
            if result.stdout.strip() == "healthy":
                return
            time.sleep(2)
        raise DrillFailed(f"app container did not become healthy within {timeout}s")

    def down_destroying_volumes(self) -> None:
        self.compose(["down", "-v"], timeout=60)

    def exec_app(self, py_code: str) -> str:
        result = _run_ok(
            ["docker", "exec", f"{self.project}-app-1", "python3", "-c", py_code],
            env=self.env,
        )
        return result.stdout.strip()

    def docker_run(self, args: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
        return _run_ok(["docker", "run", "--rm"] + args, env=self.env, timeout=timeout)


def inject_marker(drill: Drill) -> str:
    marker = f"dr-drill-{uuid.uuid4().hex}"
    drill.exec_app(
        "import sqlite3; "
        "conn = sqlite3.connect('/data/honeypot.db'); "
        "conn.execute(\"CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')))\"); "
        f"conn.execute(\"INSERT OR REPLACE INTO system_settings(key, value) VALUES ('dr_drill_marker', '{marker}')\"); "
        "conn.commit()"
    )
    drill.docker_run(
        ["-v", f"{drill.resolved()['myapp_volume']}:/var/lib/myapp", "alpine:3",
         "sh", "-c", f"echo {marker} > /var/lib/myapp/dr_drill_marker.txt"]
    )
    return marker


def read_back_marker(drill: Drill) -> str:
    return drill.exec_app(
        "import sqlite3; "
        "conn = sqlite3.connect('/data/honeypot.db'); "
        "row = conn.execute(\"SELECT value FROM system_settings WHERE key='dr_drill_marker'\").fetchone(); "
        "print(row[0] if row else '')"
    )


def check_alembic_version(drill: Drill) -> str:
    return drill.exec_app(
        "import sqlite3; "
        "conn = sqlite3.connect('/data/honeypot.db'); "
        "print(conn.execute('SELECT version_num FROM alembic_version').fetchone()[0])"
    )


def read_myapp_marker_via_volume(drill: Drill, volume: str) -> str:
    result = drill.docker_run(["-v", f"{volume}:/var/lib/myapp:ro", "alpine:3", "cat", "/var/lib/myapp/dr_drill_marker.txt"])
    return result.stdout.strip()


def backup(drill: Drill, backup_dir: Path, resolved: dict) -> dict:
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    db_backup = backup_dir / f"{ts}-honeypot.db"
    myapp_backup = backup_dir / f"{ts}-myapp.tar"

    # Not :ro -- opening a WAL-mode database (even just to read it) needs
    # SQLite to create its own -wal/-shm bookkeeping alongside the main
    # file if absent; see backup_sqlite.sh's matching comment for how
    # this was actually caught (by running this, not by reasoning).
    drill.docker_run(
        ["-v", f"{resolved['data_volume']}:/data", "-v", f"{backup_dir}:/backups", "alpine:3",
         "sh", "-c", f"apk add --no-cache sqlite >/dev/null; sqlite3 /data/honeypot.db \".backup '/backups/{db_backup.name}'\""]
    )
    drill.docker_run(
        ["-v", f"{resolved['myapp_volume']}:/var/lib/myapp:ro", "-v", f"{backup_dir}:/backups", "alpine:3",
         "tar", "-C", "/var/lib/myapp", "-cf", f"/backups/{myapp_backup.name}", "."]
    )

    drill.docker_run(
        ["--env-file", str(drill.env_file), "-v", f"{backup_dir}:/backups", resolved["app_image"],
         "python", "scripts/backup_tool.py", "encrypt", f"/backups/{db_backup.name}", f"/backups/{db_backup.name}.enc"]
    )
    drill.docker_run(
        ["--env-file", str(drill.env_file), "-v", f"{backup_dir}:/backups", resolved["app_image"],
         "python", "scripts/backup_tool.py", "encrypt", f"/backups/{myapp_backup.name}", f"/backups/{myapp_backup.name}.enc"]
    )
    (db_backup).unlink()
    (myapp_backup).unlink()
    return {"db": backup_dir / f"{db_backup.name}.enc", "myapp": backup_dir / f"{myapp_backup.name}.enc"}


def restore(drill: Drill, backups: dict, backup_dir: Path, resolved: dict) -> None:
    db_dec = backup_dir / "restored-honeypot.db"
    myapp_dec = backup_dir / "restored-myapp.tar"

    drill.docker_run(
        ["--env-file", str(drill.env_file), "-v", f"{backup_dir}:/backups", resolved["app_image"],
         "python", "scripts/backup_tool.py", "decrypt", f"/backups/{backups['db'].name}", f"/backups/{db_dec.name}"]
    )
    drill.docker_run(
        ["--env-file", str(drill.env_file), "-v", f"{backup_dir}:/backups", resolved["app_image"],
         "python", "scripts/backup_tool.py", "decrypt", f"/backups/{backups['myapp'].name}", f"/backups/{myapp_dec.name}"]
    )

    drill.docker_run(
        ["-v", f"{resolved['data_volume']}:/data", "-v", f"{backup_dir}:/backups", "alpine:3",
         "cp", f"/backups/{db_dec.name}", "/data/honeypot.db"]
    )
    drill.docker_run(
        ["-v", f"{resolved['myapp_volume']}:/var/lib/myapp", "-v", f"{backup_dir}:/backups", "alpine:3",
         "sh", "-c", f"tar -C /var/lib/myapp -xf '/backups/{myapp_dec.name}'"]
    )


def default_env_file_content(app_image: str) -> str:
    """A throwaway .env.prod-shaped file for the drill's isolated project
    -- never the real .env.prod, never real secrets. Split out from
    main() so it's testable without Docker."""
    from cryptography.fernet import Fernet

    hp_image, _, app_version = app_image.rpartition(":") if ":" in app_image else ("", "", "")
    return (
        "APP_ENV=prod\n"
        "HP_PUBLIC_HOST=dr-drill.invalid\n"
        "HP_ADMIN_HOST=admin.dr-drill.invalid\n"
        "ACME_EMAIL=dr-drill@example.invalid\n"
        "HP_PANEL_TOKEN=dr-drill-placeholder\n"
        "CLOUDFLARE_TUNNEL_TOKEN=dr-drill-placeholder\n"
        f"APP_VERSION={app_version or 'latest'}\n"
        f"HP_IMAGE={hp_image or 'ghcr.io/0x-unkwn0wn/noctisapi-pro'}\n"
        f"HP_SEED={secrets.token_hex(32)}\n"
        f"HP_BACKUP_ENCRYPTION_KEY={Fernet.generate_key().decode()}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, default=None, help="Defaults to a throwaway generated one")
    parser.add_argument("--project", default=f"dr-drill-{secrets.token_hex(4)}")
    parser.add_argument("--keep", action="store_true", help="Don't tear down the drill stack on exit")
    parser.add_argument("--app-image", default="", help="Pre-built local image tag to test against")
    args = parser.parse_args()

    tmp_dir = Path(tempfile.mkdtemp(prefix="dr_drill_"))
    backup_dir = tmp_dir / "backups"
    env_file = args.env_file or (tmp_dir / ".env.drill")

    if not args.env_file:
        env_file.write_text(default_env_file_content(args.app_image), encoding="utf-8")

    drill = Drill(env_file, args.project, args.keep, verbose=True)
    rto_start = None
    try:
        drill.log(f"project={args.project} env_file={env_file}")
        drill.log("bringing up a fresh, isolated stack")
        drill.up()
        drill.wait_healthy()
        resolved = drill.resolved()
        drill.log(f"resolved: {resolved}")

        drill.log("injecting a known marker into the live DB and /var/lib/myapp")
        marker = inject_marker(drill)
        drill.log(f"marker={marker}")

        t_backup_start = time.time()
        drill.log("backing up (sqlite3 .backup + tar + encrypt)")
        backups = backup(drill, backup_dir, resolved)
        backup_duration = time.time() - t_backup_start
        drill.log(f"backup took {backup_duration:.1f}s -> {backups}")

        rto_start = time.time()
        drill.log("SIMULATING DISASTER: docker compose down -v (destroying volumes)")
        drill.down_destroying_volumes()

        drill.log("recreating a fresh (empty) stack")
        drill.up()
        drill.wait_healthy()
        resolved_after = drill.resolved()

        drill.log("restoring from backup into the fresh volumes")
        restore(drill, backups, backup_dir, resolved_after)

        drill.log("recreating the stack again so it picks up the restored data")
        drill.compose(["restart", "app", "admin"], timeout=60)
        drill.wait_healthy()

        rto = time.time() - rto_start

        drill.log("verifying restored data matches the pre-disaster marker")
        restored_marker = read_back_marker(drill)
        if restored_marker != marker:
            raise DrillFailed(f"DB marker mismatch after restore: expected {marker!r}, got {restored_marker!r}")

        myapp_marker = read_myapp_marker_via_volume(drill, resolved_after["myapp_volume"])
        if myapp_marker != marker:
            raise DrillFailed(f"/var/lib/myapp marker mismatch after restore: expected {marker!r}, got {myapp_marker!r}")

        drill.log("verifying Alembic migration state is intact")
        version = check_alembic_version(drill)
        if not version:
            raise DrillFailed("alembic_version is empty after restore")
        drill.log(f"alembic_version={version}")

        # The gap between "backup finished" and "disaster happened" --
        # not the time since then (verification/restore time isn't part
        # of RPO, it's part of RTO).
        rpo = rto_start - (t_backup_start + backup_duration)

        print("\n=== DR drill PASSED ===")
        print(f"RTO (disaster -> verified, serving again): {rto:.1f}s")
        print(f"RPO (this drill, backup-to-disaster gap):  {rpo:.1f}s (near-zero by construction)")
        print("Real-world RPO is bounded by backup cadence (daily 02:15 UTC cron, see DEPLOY.md Sec11b)")
        print("-- worst case up to ~24h of data since the last successful scheduled backup.")
        return 0
    except DrillFailed as exc:
        print(f"\n=== DR drill FAILED: {exc} ===", file=sys.stderr)
        return 1
    finally:
        if not args.keep:
            try:
                drill.down_destroying_volumes()
            except Exception:
                pass
            shutil.rmtree(tmp_dir, ignore_errors=True)
        else:
            drill.log(f"--keep: leaving project={args.project} and {tmp_dir} in place")


if __name__ == "__main__":
    sys.exit(main())
