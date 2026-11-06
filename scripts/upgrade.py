#!/usr/bin/env python
"""
Automated versioned upgrade with staged rollout and controlled rollback
(NOC-029).

Operator flow: edit .env.prod's APP_VERSION (or MANAGED_APP_VERSION with
--managed) to the new target, then run this script instead of
`make prod-pull && make prod-up` directly. Stages, in order:

  1. Resolve the currently-RUNNING image (not just .env.prod's new value)
     as the rollback target, and the new target image via
     `docker compose config` (reuses the same resolution pattern as
     backup_sqlite.sh/dr_drill.py). No-ops cleanly if they're identical.
  2. Introspect the target image's pending Alembic revisions (run inside
     a disposable container of that exact image, never assumed from the
     local checkout) and check each for an `irreversible = True` flag
     (see migrations/README). Aborts before touching anything unless
     --force is passed, so a destructive migration can't run unattended.
  3. Take a pre-upgrade backup -- the same operations backup_sqlite.sh
     (NOC-026) performs, run directly via `docker run` rather than by
     shelling out to it (see run_backup()'s docstring for why).
  4. Pull the new image, run `migrate` to completion
     (`--exit-code-from`), then start app/admin on it.
  5. Wait for app/admin to report healthy, reusing
     scripts/ops_monitor.py's check_containers() (NOC-028) -- the same
     logic a human operator's monitoring already trusts.
  6. On migration failure or a health-check timeout: automatically roll
     back -- stop the new containers, restore the pre-upgrade backup
     (restore_backup.sh's operations, same reuse approach), and redeploy
     the previous image.
  7. On success, record the deployed image (and its resolved digest, if
     available) plus upgrade history in compose/secrets/deployment-manifest.json
     (NOC-025's manifest, extended here).

Exit codes: 0 success or already-up-to-date, 1 rolled back (or rollback
itself failed -- see stderr), 2 aborted before making any change
(nothing running yet, or an unreviewed irreversible migration).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROD_COMPOSE = _REPO_ROOT / "compose" / "docker-compose.prod.yml"
_MANAGED_COMPOSE = _REPO_ROOT / "compose" / "docker-compose.managed.yml"

sys.path.insert(0, str(_REPO_ROOT))
from scripts import ops_monitor  # noqa: E402
from scripts import init_deployment  # noqa: E402


class UpgradeFailed(Exception):
    pass


def _run(cmd: List[str], *, env: Optional[dict] = None, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, cwd=str(_REPO_ROOT), env=env, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise UpgradeFailed(f"command failed ({result.returncode}): {' '.join(cmd)}\nstderr: {result.stderr}")
    return result


def _compose_cmd(compose_files: List[Path], env_file: Path, args: List[str]) -> List[str]:
    cmd = ["docker", "compose"]
    for f in compose_files:
        cmd += ["-f", str(f)]
    cmd += ["--env-file", str(env_file)] + args
    return cmd


def compose_config(compose_files: List[Path], env_file: Path) -> dict:
    result = _run(_compose_cmd(compose_files, env_file, ["config", "--format", "json"]))
    return json.loads(result.stdout)


def running_image(compose_files: List[Path], env_file: Path, service: str = "app") -> Optional[str]:
    """The image the currently-running `service` container was started
    from. Deliberately NOT `docker compose config`, which already
    reflects any new APP_VERSION the operator has put in the env file --
    this is the rollback target. None if the service isn't running yet
    (first-ever deploy; this script doesn't apply to that case)."""
    result = _run(_compose_cmd(compose_files, env_file, ["ps", "--format", "json", "--all", service]), check=False)
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        image = entry.get("Image")
        if image:
            return image
    return None


def target_image(compose_files: List[Path], env_file: Path, service: str = "app") -> str:
    cfg = compose_config(compose_files, env_file)
    return cfg["services"][service]["image"]


def resolve_digest(image: str) -> str:
    """Best-effort content-addressed digest of the exact image that was
    pulled -- recorded in the manifest so the deployed build stays
    traceable even if the tag is reused later. Empty if unavailable (a
    locally-built image never pushed to a registry has no RepoDigests)."""
    result = _run(["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image], check=False)
    digest = result.stdout.strip()
    return digest if result.returncode == 0 and "@sha256:" in digest else ""


def current_revision(compose_files: List[Path], env_file: Path, service: str = "app") -> Optional[str]:
    """Reuses app/status_checks.py's ensure_ready() inside the currently
    running container -- the same check its own healthcheck already
    performs -- instead of reimplementing SQLite/Alembic introspection."""
    result = _run(
        _compose_cmd(compose_files, env_file, [
            "exec", "-T", service, "python", "-c",
            "import json; from app import status_checks; print(json.dumps(status_checks.ensure_ready()))",
        ]),
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout.strip())["current_revision"]
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


_PENDING_MIGRATIONS_SNIPPET = """
import json
from alembic.config import Config
from alembic.script import ScriptDirectory

cfg = Config("alembic.ini")
script = ScriptDirectory.from_config(cfg)
current = {current!r}
pending = []
seen = set()
for rev in script.walk_revisions(base=current, head="heads"):
    if rev.revision == current or rev.revision in seen:
        continue
    seen.add(rev.revision)
    pending.append({{
        "revision": rev.revision,
        "irreversible": bool(getattr(rev.module, "irreversible", False)),
        "reason": getattr(rev.module, "irreversible_reason", ""),
    }})
print(json.dumps(pending))
"""


def pending_migrations(image: str, current: str) -> List[Dict[str, object]]:
    """Introspects the pending Alembic revisions of the EXACT target
    image -- not the local checkout, which may be ahead of or behind it
    -- by running the snippet above inside a disposable container of
    that image. No DB access needed: only the image's own bundled
    migrations/ are inspected."""
    snippet = _PENDING_MIGRATIONS_SNIPPET.format(current=current)
    result = _run(["docker", "run", "--rm", image, "python", "-c", snippet], check=False)
    if result.returncode != 0:
        raise UpgradeFailed(f"could not introspect pending migrations for {image}: {result.stderr}")
    return json.loads(result.stdout.strip() or "[]")


def irreversible_gate(pending: List[Dict[str, object]], *, force: bool) -> Optional[str]:
    """Pure decision logic, kept separate from main() for testability.
    Returns an abort message if the upgrade should stop, else None."""
    irreversible = [p for p in pending if p.get("irreversible")]
    if irreversible and not force:
        lines = [
            "pending migration(s) marked irreversible -- data would not be "
            "recoverable by downgrade() alone if this upgrade needs to be rolled "
            "back after the fact. Review and re-run with --force to proceed anyway:",
        ]
        for p in irreversible:
            lines.append(f"  - {p['revision']}: {p.get('reason') or '(no reason given)'}")
        return "\n".join(lines)
    return None


def approved_target(image: str, expected_version: str) -> bool:
    """Return whether a resolved image carries the operator-approved tag."""
    expected = expected_version.strip()
    if not expected or expected == "latest" or any(char.isspace() for char in expected):
        return False
    return image == expected or image.endswith(f":{expected}")


def resolved_volumes(compose_files: List[Path], env_file: Path) -> Dict[str, str]:
    cfg = compose_config(compose_files, env_file)
    return {
        "data_volume": cfg["volumes"]["hp_prod_data"]["name"],
        "myapp_volume": cfg["volumes"]["hp_prod_myapp"]["name"],
        "app_image": cfg["services"]["app"]["image"],
    }


def run_backup(compose_files: List[Path], env_file: Path, backup_dir: Path) -> Dict[str, Path]:
    """Same operations as backup_sqlite.sh (NOC-026): a WAL-safe
    `sqlite3 .backup`, a tar of /var/lib/myapp, then encrypting both via
    scripts/backup_tool.py -- performed directly via `docker run`
    (list-form subprocess, no shell), not by shelling out to the .sh
    script. Mirrors scripts/dr_drill.py's backup(), which established
    this same reuse pattern for the same reason: there is no portable
    way to invoke an external `bash` from a plain Python process --
    on this Windows dev machine, a bare "bash" always resolves to
    System32's WSL launcher ahead of Git's own (Windows searches
    System32 before PATH for an unqualified executable name, which no
    amount of PATH reordering changes), and it can't parse a Windows
    path at all. Calling docker directly sidesteps the question
    entirely and behaves identically on the real Linux VPS target."""
    resolved = resolved_volumes(compose_files, env_file)
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    db_backup = backup_dir / f"{ts}-honeypot.db"
    myapp_backup = backup_dir / f"{ts}-myapp.tar"

    # Not :ro on the data volume -- WAL mode needs to create its own
    # -wal/-shm siblings even just to read it (same as backup_sqlite.sh).
    _run([
        "docker", "run", "--rm",
        "-v", f"{resolved['data_volume']}:/data",
        "-v", f"{backup_dir}:/backups",
        "alpine:3", "sh", "-c",
        f"apk add --no-cache sqlite >/dev/null; sqlite3 /data/honeypot.db \".backup '/backups/{db_backup.name}'\"",
    ], timeout=120)
    _run([
        "docker", "run", "--rm",
        "-v", f"{resolved['myapp_volume']}:/var/lib/myapp:ro",
        "-v", f"{backup_dir}:/backups",
        "alpine:3", "tar", "-C", "/var/lib/myapp", "-cf", f"/backups/{myapp_backup.name}", ".",
    ], timeout=60)
    for backup in (db_backup, myapp_backup):
        _run([
            "docker", "run", "--rm", "--env-file", str(env_file),
            "-v", f"{backup_dir}:/backups", resolved["app_image"],
            "python", "scripts/backup_tool.py", "encrypt", f"/backups/{backup.name}", f"/backups/{backup.name}.enc",
        ], timeout=60)
        backup.unlink()
    return {"db": backup_dir / f"{db_backup.name}.enc", "myapp": backup_dir / f"{myapp_backup.name}.enc"}


def _assert_volume_not_in_use(volume: str) -> None:
    result = _run(["docker", "ps", "-q", "--filter", f"volume={volume}"], check=False)
    if result.stdout.strip():
        raise UpgradeFailed(f"volume {volume} is still in use by a running container -- refusing to restore into it")


def restore_backup(env_file: Path, kind: str, backup_file: Path, *, volume: str, app_image: str) -> None:
    """Mirrors restore_backup.sh's (NOC-027) operations -- see
    run_backup()'s docstring for why this calls docker directly instead
    of shelling out to the .sh script. Hard-refuses (not just warns) if
    the target volume is still in use, same guard restore_backup.sh
    enforces."""
    _assert_volume_not_in_use(volume)
    backup_dir = backup_file.parent
    decrypted = backup_dir / (backup_file.stem + ".restore")
    try:
        _run([
            "docker", "run", "--rm", "--env-file", str(env_file),
            "-v", f"{backup_dir}:/backups", app_image,
            "python", "scripts/backup_tool.py", "decrypt", f"/backups/{backup_file.name}", f"/backups/{decrypted.name}",
        ], timeout=60)
        if kind == "db":
            _run([
                "docker", "run", "--rm",
                "-v", f"{volume}:/data",
                "-v", f"{backup_dir}:/backups",
                "alpine:3", "cp", f"/backups/{decrypted.name}", "/data/honeypot.db",
            ], timeout=60)
        else:
            _run([
                "docker", "run", "--rm",
                "-v", f"{volume}:/var/lib/myapp",
                "-v", f"{backup_dir}:/backups",
                "alpine:3", "sh", "-c", f"rm -rf /var/lib/myapp/* && tar -C /var/lib/myapp -xf '/backups/{decrypted.name}'",
            ], timeout=60)
    finally:
        decrypted.unlink(missing_ok=True)


def wait_healthy(compose_files: List[Path], env_file: Path, *, timeout: int, services=("app", "admin")) -> bool:
    deadline = time.time() + timeout
    while True:
        checks = ops_monitor.check_containers(compose_files, env_file)
        relevant = [c for c in checks if c.name.split(":", 1)[-1] in services]
        if relevant and all(c.ok for c in relevant):
            return True
        if time.time() >= deadline:
            return False
        time.sleep(3)


def record_upgrade(
    manifest_path: Path, *, previous_image: str, new_image: str, digest: str, result: str, reason: str = ""
) -> dict:
    manifest = init_deployment.load_manifest(manifest_path)
    manifest["updated_at"] = init_deployment._utc_now()
    history = manifest.setdefault("upgrade_history", [])
    entry = {
        "timestamp": manifest["updated_at"],
        "from_image": previous_image,
        "to_image": new_image,
        "result": result,
    }
    if digest:
        entry["digest"] = digest
    if reason:
        entry["reason"] = reason
    history.append(entry)
    del history[:-20]  # cap unbounded growth; recent history is what matters operationally
    if result == "success":
        manifest["app_image"] = new_image
        manifest["previous_app_image"] = previous_image
        if digest:
            manifest["app_image_digest"] = digest
    # NOC-031: stamp schema_version/status here too, in case this is the
    # very first write to this manifest (upgrade.py run without
    # init_deployment.py ever having run first).
    from scripts.deployment_manifest import stamp_schema

    stamp_schema(manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _rollback(
    compose_files: List[Path],
    env_file: Path,
    *,
    previous_image: str,
    new_image: str,
    backups: Optional[Dict[str, Path]],
    manifest_path: Path,
    reason: str,
) -> int:
    print(f"[upgrade] ROLLING BACK: {reason}", file=sys.stderr)
    try:
        # Resolved before `down` so the image ref is available either way;
        # volume names don't depend on anything being up or down.
        resolved = resolved_volumes(compose_files, env_file)
        _run(_compose_cmd(compose_files, env_file, ["down"]), timeout=120, check=False)

        if backups:
            print("[upgrade] restoring pre-upgrade backup", file=sys.stderr)
            # Decrypt/restore using the PREVIOUS (known-good) image, not
            # the new one being rolled back from -- it's the image we're
            # reverting to anyway, and the new one is exactly what may be
            # broken.
            restore_backup(env_file, "db", backups["db"], volume=resolved["data_volume"], app_image=previous_image)
            restore_backup(
                env_file, "myapp", backups["myapp"], volume=resolved["myapp_volume"], app_image=previous_image
            )
        else:
            print(
                "[upgrade] WARNING: no backup was taken (--skip-backup) -- cannot restore "
                "data, only reverting the application image",
                file=sys.stderr,
            )

        _, _, previous_tag = previous_image.rpartition(":")
        rollback_env = dict(os.environ)
        rollback_env["APP_VERSION"] = previous_tag
        # Managed Compose resolves MANAGED_APP_VERSION after the base
        # Compose file, so setting APP_VERSION alone would silently bring
        # the failed target back during rollback.
        if _MANAGED_COMPOSE in compose_files:
            rollback_env["MANAGED_APP_VERSION"] = previous_tag
        _run(
            _compose_cmd(compose_files, env_file, ["up", "-d", "migrate", "app", "admin"]),
            env=rollback_env, timeout=180, check=False,
        )
        rolled_back_healthy = wait_healthy(compose_files, env_file, timeout=90)

        record_upgrade(
            manifest_path, previous_image=previous_image, new_image=new_image,
            digest="", result="rolled_back", reason=reason,
        )
        if rolled_back_healthy:
            print(f"[upgrade] rollback complete -- back on {previous_image}", file=sys.stderr)
        else:
            print(
                f"[upgrade] rollback issued but {previous_image} did not report healthy -- "
                "needs manual attention",
                file=sys.stderr,
            )
    except Exception as exc:  # pragma: no cover - last-resort guard
        print(f"[upgrade] CRITICAL: rollback itself failed: {exc} -- manual intervention required", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--managed", action="store_true", help="Also layer compose/docker-compose.managed.yml")
    parser.add_argument("--env-file", type=Path, default=_REPO_ROOT / ".env.prod")
    parser.add_argument("--backup-dir", type=Path, default=_REPO_ROOT / "backups")
    parser.add_argument(
        "--manifest", type=Path, default=_REPO_ROOT / "compose" / "secrets" / "deployment-manifest.json"
    )
    parser.add_argument("--health-timeout", type=int, default=120)
    parser.add_argument(
        "--force", action="store_true",
        help="Proceed even if a pending migration is marked irreversible",
    )
    parser.add_argument(
        "--skip-backup", action="store_true",
        help="Testing only -- an automated rollback cannot restore data without a backup",
    )
    parser.add_argument(
        "--expected-version", default="",
        help="Abort unless the resolved target image has this approved immutable tag",
    )
    args = parser.parse_args()

    compose_files = [_PROD_COMPOSE] + ([_MANAGED_COMPOSE] if args.managed else [])

    previous_image = running_image(compose_files, args.env_file, "app")
    if previous_image is None:
        print(
            "[upgrade] app is not currently running -- nothing to upgrade. "
            "Use `docker compose up -d` (or `make prod-up`) for a first deploy.",
            file=sys.stderr,
        )
        return 2

    new_image = target_image(compose_files, args.env_file, "app")
    if previous_image == new_image:
        print(f"[upgrade] already running {new_image} -- nothing to do.", file=sys.stderr)
        return 0

    if args.expected_version and not approved_target(new_image, args.expected_version):
        print(
            f"[upgrade] ABORTED: resolved target {new_image!r} does not match "
            f"approved version {args.expected_version!r}",
            file=sys.stderr,
        )
        return 2

    print(f"[upgrade] {previous_image} -> {new_image}", file=sys.stderr)

    pending: List[Dict[str, object]] = []
    current_rev = current_revision(compose_files, args.env_file, "app")
    if current_rev:
        try:
            pending = pending_migrations(new_image, current_rev)
        except UpgradeFailed as exc:
            print(f"[upgrade] WARNING: could not introspect pending migrations: {exc}", file=sys.stderr)

    abort_message = irreversible_gate(pending, force=args.force)
    if abort_message:
        print(f"[upgrade] ABORTED: {abort_message}", file=sys.stderr)
        return 2
    for p in pending:
        tag = "IRREVERSIBLE" if p.get("irreversible") else "reversible"
        print(f"[upgrade] pending migration {p['revision']} ({tag})", file=sys.stderr)

    backups = None
    if not args.skip_backup:
        print("[upgrade] taking pre-upgrade backup", file=sys.stderr)
        backups = run_backup(compose_files, args.env_file, args.backup_dir)
        print(f"[upgrade] backup: {backups}", file=sys.stderr)

    print("[upgrade] pulling new image", file=sys.stderr)
    try:
        _run(_compose_cmd(compose_files, args.env_file, ["pull", "migrate", "app", "admin"]), timeout=600)
    except UpgradeFailed as exc:
        print(f"[upgrade] ABORTED before switching: {exc}", file=sys.stderr)
        print("[upgrade] the previous version is still running untouched -- no rollback needed.", file=sys.stderr)
        return 2

    print("[upgrade] running migrations", file=sys.stderr)
    migrate_result = _run(
        _compose_cmd(compose_files, args.env_file, ["up", "--exit-code-from", "migrate", "migrate"]),
        timeout=180, check=False,
    )
    if migrate_result.returncode != 0:
        return _rollback(
            compose_files, args.env_file, previous_image=previous_image, new_image=new_image,
            backups=backups, manifest_path=args.manifest, reason="migration failed",
        )

    print("[upgrade] starting app/admin on the new image", file=sys.stderr)
    _run(_compose_cmd(compose_files, args.env_file, ["up", "-d", "app", "admin"]), timeout=180, check=False)

    print("[upgrade] waiting for health", file=sys.stderr)
    if not wait_healthy(compose_files, args.env_file, timeout=args.health_timeout):
        return _rollback(
            compose_files, args.env_file, previous_image=previous_image, new_image=new_image,
            backups=backups, manifest_path=args.manifest, reason="post-upgrade health check failed",
        )

    digest = resolve_digest(new_image)
    record_upgrade(
        args.manifest, previous_image=previous_image, new_image=new_image, digest=digest, result="success",
    )
    print(f"[upgrade] SUCCESS: now running {new_image}" + (f" ({digest})" if digest else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
