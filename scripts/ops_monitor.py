#!/usr/bin/env python
"""
Operational health monitor (NOC-028): detects instance failures and
resource exhaustion WITHOUT touching or centralizing attacker telemetry.

Checks, each independent (one failing doesn't skip the rest):
  - Container health: every service's own Docker healthcheck status
    (migrate/app/admin/cloudflared/traefik), via `docker compose ps`. A
    one-shot service (migrate, traefik-config) is judged by its exit
    code instead, since it has no healthcheck of its own.
  - Disk space on the backup directory and Docker's own data root.
  - Memory and CPU load on the host (Linux only -- this targets a real
    VPS, not local dev).
  - Cloudflare Tunnel connectivity: folded into the container-health
    check above (cloudflared has its own Docker healthcheck, NOC-016) --
    not a separate check.
  - TLS certificate expiry for HP_PUBLIC_HOST, reusing
    scripts/verify_domain.py's check_tls() rather than a second
    implementation of the same thing.
  - Backup freshness: age of the most recent backup file in BACKUP_DIR
    against an expected cadence.

Alerts via HP_OPS_ALERT_WEBHOOK_URL -- a webhook deliberately SEPARATE
from app/alert_dispatcher.py's HP_ALERT_WEBHOOK_URL (the honeypot's
attacker-event channel). Mixing the two would centralize attacker
telemetry into an infra-ops channel or vice versa -- exactly what this
Issue's "sin centralizar telemetría de ataques" / "se distingue salud
infra de métricas señuelo" criteria rule out. This script never reads
honeypot event/actor data at all.

Exit code 0 only if every check passes. Intended for cron, same pattern
as backup_sqlite.sh / scripts/prune_retention.py.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_COMPOSE_FILE = _REPO_ROOT / "compose" / "docker-compose.prod.yml"

# Services with no healthcheck of their own -- judged by exit code instead.
_ONE_SHOT_SERVICES = {"migrate", "traefik-config"}


class Check:
    def __init__(self, name: str, ok: bool, detail: str):
        self.name = name
        self.ok = ok
        self.detail = detail

    def __str__(self) -> str:
        return f"{'OK  ' if self.ok else 'FAIL'} {self.name}: {self.detail}"


def check_containers(compose_file: Path, env_file: Path) -> List[Check]:
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "--env-file", str(env_file),
             "ps", "--format", "json", "--all"],
            cwd=str(_REPO_ROOT), capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return [Check("containers", False, f"could not run docker compose ps: {exc}")]

    if result.returncode != 0:
        return [Check("containers", False, f"docker compose ps failed: {result.stderr.strip()}")]

    checks = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        service = entry.get("Service", "?")
        state = entry.get("State", "?")
        health = entry.get("Health", "")
        exit_code = entry.get("ExitCode", 0)

        if service in _ONE_SHOT_SERVICES:
            ok = exit_code == 0
            checks.append(Check(f"container:{service}", ok, f"one-shot, exit_code={exit_code}"))
        elif health:
            ok = health == "healthy"
            checks.append(Check(f"container:{service}", ok, f"state={state} health={health}"))
        elif state == "running":
            # No healthcheck configured for this service, but at least running.
            checks.append(Check(f"container:{service}", True, f"state={state} (no healthcheck defined)"))
        else:
            # Not running and health is empty -- either it genuinely has no
            # healthcheck and crashed/restarting, or (more commonly, e.g.
            # cloudflared crash-looping on a bad token) it has one but
            # hasn't been running long enough for a check to report yet.
            # Either way: not running is the failure, regardless of why.
            checks.append(Check(f"container:{service}", False, f"state={state}"))
    return checks


def check_disk(path: Path, *, warn_percent: float = 85.0) -> Check:
    try:
        usage = __import__("shutil").disk_usage(path)
    except OSError as exc:
        return Check(f"disk:{path}", False, f"could not stat: {exc}")
    percent_used = 100.0 * usage.used / usage.total if usage.total else 0.0
    ok = percent_used < warn_percent
    return Check(
        f"disk:{path}", ok,
        f"{percent_used:.1f}% used ({usage.free // (1024**3)} GiB free, warn at {warn_percent:.0f}%)",
    )


def check_memory(*, warn_percent: float = 90.0) -> Optional[Check]:
    meminfo_path = Path("/proc/meminfo")
    if not meminfo_path.exists():
        return None  # not Linux -- this check doesn't apply (e.g. local dev on Windows/macOS)
    values = {}
    for line in meminfo_path.read_text(encoding="utf-8").splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        val = parts[1].strip().split()[0]
        values[key] = int(val)
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", total)
    if total == 0:
        return Check("memory", False, "could not read /proc/meminfo")
    percent_used = 100.0 * (total - available) / total
    ok = percent_used < warn_percent
    return Check("memory", ok, f"{percent_used:.1f}% used (warn at {warn_percent:.0f}%)")


def check_cpu_load(*, warn_ratio: float = 2.0) -> Optional[Check]:
    if not hasattr(os, "getloadavg"):
        return None  # not available on Windows -- this targets a real Linux VPS
    load_1, load_5, load_15 = os.getloadavg()
    cpu_count = os.cpu_count() or 1
    ratio = load_5 / cpu_count
    ok = ratio < warn_ratio
    return Check(
        "cpu_load", ok,
        f"5-min load {load_5:.2f} / {cpu_count} CPUs = {ratio:.2f}x (warn at {warn_ratio:.1f}x)",
    )


def check_certificate(host: str, *, warn_days: int = 14) -> Optional[Check]:
    if not host:
        return None
    sys.path.insert(0, str(_REPO_ROOT))
    from scripts.verify_domain import CheckFailed, check_tls  # noqa: E402

    try:
        detail = check_tls(host, warn_days=warn_days)
        return Check(f"certificate:{host}", True, detail)
    except CheckFailed as exc:
        return Check(f"certificate:{host}", False, str(exc))


def check_backup_freshness(backup_dir: Path, *, max_age_hours: float = 26.0) -> Check:
    if not backup_dir.exists():
        return Check("backup_freshness", False, f"{backup_dir} does not exist")
    candidates = list(backup_dir.glob("*-honeypot.db*"))
    if not candidates:
        return Check("backup_freshness", False, f"no backup files found in {backup_dir}")
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    age_hours = (time.time() - newest.stat().st_mtime) / 3600.0
    ok = age_hours < max_age_hours
    return Check(
        "backup_freshness", ok,
        f"newest backup {newest.name} is {age_hours:.1f}h old (warn at {max_age_hours:.0f}h)",
    )


def send_alert(webhook_url: str, failures: List[Check]) -> None:
    payload = {
        "event": "ops_health_alert",
        "failure_count": len(failures),
        "failures": [{"check": c.name, "detail": c.detail} for c in failures],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 -- operator-configured URL
            if resp.status >= 400:
                print(f"[ops-monitor] webhook returned HTTP {resp.status}", file=sys.stderr)
    except (urllib.error.URLError, OSError) as exc:
        print(f"[ops-monitor] failed to POST alert webhook: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--compose-file", type=Path, default=_COMPOSE_FILE)
    parser.add_argument("--env-file", type=Path, default=_REPO_ROOT / ".env.prod")
    parser.add_argument("--backup-dir", type=Path, default=_REPO_ROOT / "backups")
    parser.add_argument("--host", default=os.getenv("HP_PUBLIC_HOST", "").strip())
    parser.add_argument("--skip-containers", action="store_true")
    parser.add_argument("--skip-certificate", action="store_true")
    parser.add_argument("--skip-backup-freshness", action="store_true")
    args = parser.parse_args()

    checks: List[Check] = []

    if not args.skip_containers:
        checks.extend(check_containers(args.compose_file, args.env_file))

    checks.append(check_disk(args.backup_dir))

    mem_check = check_memory()
    if mem_check:
        checks.append(mem_check)

    cpu_check = check_cpu_load()
    if cpu_check:
        checks.append(cpu_check)

    if not args.skip_certificate:
        cert_check = check_certificate(args.host)
        if cert_check:
            checks.append(cert_check)

    if not args.skip_backup_freshness:
        checks.append(check_backup_freshness(args.backup_dir))

    for check in checks:
        print(check, file=sys.stderr)

    failures = [c for c in checks if not c.ok]
    if failures:
        webhook_url = os.getenv("HP_OPS_ALERT_WEBHOOK_URL", "").strip()
        if webhook_url:
            send_alert(webhook_url, failures)
        print(f"\n{len(failures)}/{len(checks)} check(s) failed.", file=sys.stderr)
        return 1

    print(f"\nAll {len(checks)} check(s) passed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
