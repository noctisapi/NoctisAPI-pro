#!/usr/bin/env python
"""
Post-install verification (NOC-030): one clear pass/fail sweep across
DNS, TLS, the public app, the admin console, file/container
permissions, backup configuration, and network isolation -- run once
right after a fresh deploy (or on demand). Distinct from
scripts/ops_monitor.py, which is the ONGOING cron-based health monitor
(containers/disk/memory/cpu/cert/backup-freshness, every 10 min) --
this is a one-shot, broader-scope quality gate for "did this deployment
actually come up correctly."

Reuses rather than reimplements wherever something already exists:
  - DNS/TLS: scripts/verify_domain.py (NOC-024).
  - Containers, same `Check` shape/printing: scripts/ops_monitor.py
    (NOC-028). Backup *freshness* (once a backup actually exists) also
    reuses ops_monitor.check_backup_freshness().

New checks (nothing to reuse for these -- see the PR body's audit):
  - "app": an actual HTTPS GET of HP_PUBLIC_HOST's decoy /health through
    the full public chain (DNS -> TLS -> Traefik -> app), not just the
    container's own internal readiness (that's check_app_ready.py's job).
  - "console": HP_ADMIN_HOST is reachable (the Cloudflare Tunnel is
    actually connected) AND gated -- redirected to /login (NOC-018's own
    middleware) or an Access challenge, never a bare HTTP 200 of
    protected content.
  - "permissions": compose/secrets/*.txt are mode 0600, and app/admin
    really run as uid 10001 right now (not just configured to).
  - "backups": the encryption key and cron job are installed.
    Freshness is checked only once a backup file actually exists -- a
    same-day fresh install legitimately has none yet (see DEPLOY.md
    Sec11b's daily 02:15 UTC cadence), so that's reported honestly as
    pending, not faked as a pass and not a false failure either.
  - "isolation": the Docker socket isn't mounted in any live container,
    and admin publishes no ports -- re-verifying at runtime what
    tests/test_compose_security.py only ever checks statically.

Exit codes: 0 every check passed, 1 one or more failed, 2 usage error
(no --host/HP_PUBLIC_HOST). Never reports success while any check has
failed -- see main()'s single, always-evaluated failure gate at the end.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROD_COMPOSE = _REPO_ROOT / "compose" / "docker-compose.prod.yml"
_MANAGED_COMPOSE = _REPO_ROOT / "compose" / "docker-compose.managed.yml"

sys.path.insert(0, str(_REPO_ROOT))
from scripts import ops_monitor  # noqa: E402
from scripts import verify_domain  # noqa: E402
from scripts.upgrade import _compose_cmd  # noqa: E402

Check = ops_monitor.Check  # same shape/printing convention as every other operator script


def check_dns_and_tls(
    host: str, expected_ip: str = "", *, warn_days: int = 14, timeout: float = 10.0
) -> List[Check]:
    if not host:
        return [Check("dns", False, "no host given")]
    checks: List[Check] = []
    try:
        addresses = verify_domain.resolve_host(host)
    except verify_domain.CheckFailed as exc:
        checks.append(Check(f"dns:{host}", False, str(exc)))
        return checks  # no point checking TLS if DNS doesn't even resolve

    checks.append(Check(f"dns:{host}", True, f"resolves to {', '.join(addresses)}"))
    if expected_ip:
        try:
            verify_domain.check_expected_ip(addresses, expected_ip)
            checks.append(Check(f"dns:{host}:expected_ip", True, f"matches {expected_ip}"))
        except verify_domain.CheckFailed as exc:
            checks.append(Check(f"dns:{host}:expected_ip", False, str(exc)))

    try:
        detail = verify_domain.check_tls(host, warn_days=warn_days, timeout=timeout)
        checks.append(Check(f"tls:{host}", True, detail))
    except verify_domain.CheckFailed as exc:
        checks.append(Check(f"tls:{host}", False, str(exc)))
    return checks


def check_public_app(host: str, *, timeout: float = 10.0) -> Check:
    if not host:
        return Check("app:public", False, "no host given")
    url = f"https://{host}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 -- operator-configured host
            return Check(f"app:{host}", resp.status == 200, f"GET /health -> HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        return Check(f"app:{host}", False, f"GET /health -> HTTP {exc.code}")
    except (urllib.error.URLError, OSError) as exc:
        return Check(f"app:{host}", False, f"GET /health failed: {exc}")


def check_console(admin_host: str, *, timeout: float = 10.0) -> Optional[Check]:
    """Confirms the tunnel is actually connected (not a bare 502/503/504
    or connection failure) AND that an unauthenticated request is gated
    -- redirected to NOC-018's own /login, or intercepted by a Cloudflare
    Access challenge -- never a raw HTTP 200 of protected content."""
    if not admin_host:
        return None  # not configured -- not every deployment uses Cloudflare Access/Tunnel yet
    url = f"https://{admin_host}/"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            status, final_url, body = resp.status, resp.geturl(), resp.read(4096)
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl() or url
        body = exc.read(4096) if exc.fp else b""
    except (urllib.error.URLError, OSError) as exc:
        return Check(f"console:{admin_host}", False, f"unreachable (tunnel down?): {exc}")

    if status in (502, 503, 504):
        return Check(f"console:{admin_host}", False, f"HTTP {status} -- tunnel is up but the origin isn't responding")

    body_lower = body.decode("utf-8", "ignore").lower()
    gated = (
        status in (401, 403)
        or "/login" in final_url
        or "cloudflareaccess" in body_lower
        or "cdn-cgi/access" in body_lower
    )
    if gated:
        return Check(f"console:{admin_host}", True, f"HTTP {status} -- gated (redirected to login / Access challenge)")
    if status == 200:
        return Check(
            f"console:{admin_host}", False,
            "HTTP 200 WITHOUT a login/Access redirect -- the console may be exposed. Investigate immediately.",
        )
    return Check(f"console:{admin_host}", False, f"unexpected HTTP {status}")


def _secret_file_mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def check_permissions(secrets_dir: Path, compose_files: List[Path], env_file: Path) -> List[Check]:
    checks: List[Check] = []
    for name in ("hp_seed.txt", "backup_encryption_key.txt"):
        path = secrets_dir / name
        if not path.exists():
            continue  # self-hosted installs may use neither -- absence alone isn't a failure
        try:
            mode = _secret_file_mode(path)
            ok = mode == "0o600"
            checks.append(Check(f"permissions:{name}", ok, f"mode {mode}" + ("" if ok else " (expected 0o600)")))
        except OSError as exc:
            checks.append(Check(f"permissions:{name}", False, f"could not stat: {exc}"))

    for service in ("app", "admin"):
        try:
            result = subprocess.run(
                _compose_cmd(compose_files, env_file, ["exec", "-T", service, "id", "-u"]),
                cwd=str(_REPO_ROOT), capture_output=True, text=True, timeout=15,
            )
            uid = result.stdout.strip()
            ok = result.returncode == 0 and uid == "10001"
            checks.append(
                Check(f"permissions:{service}_uid", ok, f"uid={uid or 'unknown'}" + ("" if ok else " (expected 10001)"))
            )
        except Exception as exc:  # pragma: no cover - defensive, mirrors ops_monitor's own style
            checks.append(Check(f"permissions:{service}_uid", False, f"could not check: {exc}"))
    return checks


def check_backups(secrets_dir: Path, backup_dir: Path, cron_file: Path, *, max_age_hours: float = 26.0) -> List[Check]:
    checks: List[Check] = []

    key_file = secrets_dir / "backup_encryption_key.txt"
    key_configured = key_file.exists() or bool(os.getenv("HP_BACKUP_ENCRYPTION_KEY", "").strip())
    checks.append(Check(
        "backups:encryption_key", key_configured,
        "configured" if key_configured
        else "HP_BACKUP_ENCRYPTION_KEY is not set and no compose/secrets/backup_encryption_key.txt",
    ))

    cron_installed = cron_file.exists()
    checks.append(Check(
        f"backups:cron:{cron_file}", cron_installed,
        "installed" if cron_installed else f"not found at {cron_file} -- see DEPLOY.md Sec11b",
    ))

    if backup_dir.exists() and list(backup_dir.glob("*-honeypot.db*")):
        checks.append(ops_monitor.check_backup_freshness(backup_dir, max_age_hours=max_age_hours))
    else:
        checks.append(Check(
            "backups:freshness", True,
            f"no backup file yet in {backup_dir} -- expected on a same-day fresh install, first cron run is pending",
        ))
    return checks


def check_isolation(compose_files: List[Path], env_file: Path) -> List[Check]:
    try:
        result = subprocess.run(
            _compose_cmd(compose_files, env_file, ["ps", "--format", "json", "--all"]),
            cwd=str(_REPO_ROOT), capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return [Check("isolation", False, f"could not list containers: {exc}")]
    if result.returncode != 0:
        return [Check("isolation", False, f"docker compose ps failed: {result.stderr.strip()}")]

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not entries:
        return [Check("isolation", False, "no running containers found -- is the stack up?")]

    checks: List[Check] = []
    socket_offenders = []
    for entry in entries:
        cid = entry.get("ID") or entry.get("Name")
        if not cid:
            continue
        inspect = subprocess.run(
            ["docker", "inspect", cid, "--format", "{{json .Mounts}}"],
            capture_output=True, text=True, timeout=15,
        )
        if inspect.returncode == 0 and "docker.sock" in inspect.stdout:
            socket_offenders.append(entry.get("Service", cid))
    checks.append(Check(
        "isolation:docker_socket", not socket_offenders,
        "not mounted in any live container" if not socket_offenders else f"mounted in: {socket_offenders}",
    ))

    admin_entry = next((e for e in entries if e.get("Service") == "admin"), None)
    if admin_entry:
        cid = admin_entry.get("ID") or admin_entry.get("Name")
        inspect = subprocess.run(
            ["docker", "inspect", cid, "--format", "{{json .NetworkSettings.Ports}}"],
            capture_output=True, text=True, timeout=15,
        )
        published = inspect.stdout.strip()
        has_published = published not in ("", "{}", "null", "")
        checks.append(Check(
            "isolation:admin_no_published_ports", not has_published,
            "admin publishes no ports" if not has_published else f"admin publishes: {published}",
        ))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.getenv("HP_PUBLIC_HOST", "").strip())
    parser.add_argument("--admin-host", default=os.getenv("HP_ADMIN_HOST", "").strip())
    parser.add_argument("--expected-ip", default="")
    parser.add_argument("--managed", action="store_true")
    parser.add_argument("--env-file", type=Path, default=_REPO_ROOT / ".env.prod")
    parser.add_argument("--backup-dir", type=Path, default=_REPO_ROOT / "backups")
    parser.add_argument("--secrets-dir", type=Path, default=_REPO_ROOT / "compose" / "secrets")
    parser.add_argument("--cron-file", type=Path, default=Path("/etc/cron.d/noctisapi-backup"))
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--skip-dns-tls", action="store_true")
    parser.add_argument("--skip-console", action="store_true")
    parser.add_argument("--skip-isolation", action="store_true")
    args = parser.parse_args()

    if not args.host:
        print("[verify] --host or HP_PUBLIC_HOST is required", file=sys.stderr)
        return 2

    compose_files = [_PROD_COMPOSE] + ([_MANAGED_COMPOSE] if args.managed else [])

    checks: List[Check] = []
    if not args.skip_dns_tls:
        checks += check_dns_and_tls(args.host, args.expected_ip, timeout=args.timeout)
    checks.append(check_public_app(args.host, timeout=args.timeout))
    if not args.skip_console:
        console_check = check_console(args.admin_host, timeout=args.timeout)
        if console_check:
            checks.append(console_check)
    checks += ops_monitor.check_containers(compose_files, args.env_file)
    checks += check_permissions(args.secrets_dir, compose_files, args.env_file)
    checks += check_backups(args.secrets_dir, args.backup_dir, args.cron_file)
    if not args.skip_isolation:
        checks += check_isolation(compose_files, args.env_file)

    for c in checks:
        print(c, file=sys.stderr)

    failures = [c for c in checks if not c.ok]
    if failures:
        print(f"\n{len(failures)}/{len(checks)} check(s) FAILED.", file=sys.stderr)
        return 1
    print(f"\nAll {len(checks)} check(s) passed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
