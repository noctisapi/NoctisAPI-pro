#!/usr/bin/env python
"""
Verify a customer's public decoy domain is correctly configured (NOC-024).

Checks, in order, and reports each one clearly (never a raw traceback):
  1. DNS resolution for --host (A/AAAA) -- fails if it doesn't resolve at all.
  2. If --expected-ip is given (the VPS's own public IP), confirms the
     resolved address actually matches it. Traefik's ACME HTTP-01
     challenge (compose/docker-compose.prod.yml) requires the domain to
     point directly at this VPS -- no CDN/proxy in front of it -- so a
     mismatch here means the cert will fail to issue before Traefik's own
     logs ever surface why.
  3. Unless --skip-tls, a live TLS handshake to https://--host, confirming
     the certificate validates, matches the hostname, and isn't within
     --warn-days of expiring (default 14). Traefik/ACME's automatic
     renewal is already configured; this confirms it's actually working,
     it doesn't implement the renewal itself.

Exit code 0 only if every requested check passes. Run manually post-deploy,
or from your own deploy pipeline -- deliberately NOT part of the Docker
healthcheck (scripts/check_app_ready.py): an external DNS/TLS dependency
has no business gating container liveness every 30 seconds.

Examples:
  python scripts/verify_domain.py --host api.example.com --expected-ip 203.0.113.10
  python scripts/verify_domain.py --host admin.example.com --skip-tls --no-ip-check
    # HP_ADMIN_HOST goes through Cloudflare Tunnel (NOC-016), not this
    # VPS's IP or Traefik's ACME -- only DNS resolution is meaningful here.
"""
from __future__ import annotations

import argparse
import datetime
import os
import socket
import ssl
import sys
from typing import List, Optional


class CheckFailed(Exception):
    pass


def resolve_host(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise CheckFailed(f"DNS: '{host}' does not resolve ({exc})")
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise CheckFailed(f"DNS: '{host}' resolved to no addresses")
    return addresses


def check_expected_ip(addresses: List[str], expected_ip: str) -> None:
    if expected_ip not in addresses:
        raise CheckFailed(
            f"DNS: resolved to {addresses}, expected '{expected_ip}' among them -- "
            "the domain does not point at this deployment"
        )


def check_tls(host: str, *, port: int = 443, warn_days: int = 14, timeout: float = 10.0) -> str:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        raise CheckFailed(f"TLS: certificate for '{host}' failed validation ({exc})")
    except (OSError, socket.timeout) as exc:
        raise CheckFailed(f"TLS: could not connect to '{host}:{port}' ({exc})")

    not_after_raw = cert.get("notAfter")
    if not not_after_raw:
        raise CheckFailed(f"TLS: certificate for '{host}' has no expiry date")
    not_after = datetime.datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc
    )
    days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
    if days_left < 0:
        raise CheckFailed(f"TLS: certificate for '{host}' expired {-days_left} day(s) ago")
    if days_left < warn_days:
        raise CheckFailed(
            f"TLS: certificate for '{host}' expires in {days_left} day(s) (< --warn-days {warn_days}) "
            "-- ACME renewal may not be working"
        )
    return f"TLS: certificate for '{host}' valid, expires in {days_left} day(s)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.getenv("HP_PUBLIC_HOST", "").strip(), help="Domain to verify")
    parser.add_argument("--expected-ip", default="", help="VPS public IP the domain must resolve to")
    parser.add_argument("--no-ip-check", action="store_true", help="Skip the --expected-ip comparison")
    parser.add_argument("--skip-tls", action="store_true", help="Skip the live TLS handshake check")
    parser.add_argument("--warn-days", type=int, default=14, help="Fail if the cert expires within this many days")
    args = parser.parse_args()

    host = args.host.strip()
    if not host:
        print("ERROR: no --host given and HP_PUBLIC_HOST is not set", file=sys.stderr)
        return 2

    failures: List[str] = []

    try:
        addresses = resolve_host(host)
        print(f"OK   DNS: '{host}' resolves to {addresses}")
        if args.expected_ip and not args.no_ip_check:
            check_expected_ip(addresses, args.expected_ip)
            print(f"OK   DNS: resolved address matches expected '{args.expected_ip}'")
    except CheckFailed as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        failures.append(str(exc))
        addresses = []

    if not args.skip_tls and addresses:
        try:
            print(f"OK   {check_tls(host, warn_days=args.warn_days)}")
        except CheckFailed as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            failures.append(str(exc))
    elif not args.skip_tls:
        print("SKIP TLS: no resolved address to connect to", file=sys.stderr)

    if failures:
        print(f"\n{len(failures)} check(s) failed for '{host}'.", file=sys.stderr)
        return 1
    print(f"\nAll checks passed for '{host}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
