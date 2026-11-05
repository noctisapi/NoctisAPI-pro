#!/usr/bin/env python
"""Container healthcheck for the internal application state.

NOC-028: optionally also checks the HTTP server itself is responding
(--http-port), not just the DB migration state -- the DB being fine
doesn't mean uvicorn hasn't hung or crashed while the process is still
technically running. Always a plain, local 127.0.0.1 request from inside
the container's own network namespace -- this never exposes anything
externally, same as the DB check it's alongside.

--http-port is optional and defaults to skipped, so this stays a drop-in
replacement for every existing bare `python scripts/check_app_ready.py`
invocation (compose/docker-compose.{dev,prod,staging}.yml).
"""
import argparse
import sys
import urllib.error
import urllib.request

from app import status_checks


def _check_http(port: int, timeout: float = 3.0) -> None:
    url = f"http://127.0.0.1:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 -- fixed localhost URL
            if resp.status != 200:
                raise RuntimeError(f"GET {url} returned HTTP {resp.status}")
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"GET {url} failed: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--http-port", type=int, default=None,
        help="Also GET http://127.0.0.1:<port>/health and require a 200 (e.g. 8000 for app, 9001 for admin)",
    )
    args = parser.parse_args()

    try:
        state = status_checks.ensure_ready()
    except Exception as exc:  # pragma: no cover - invoked by Docker
        print(f"[ready-check] db failure: {exc}", file=sys.stderr)
        return 1

    if args.http_port is not None:
        try:
            _check_http(args.http_port)
        except Exception as exc:  # pragma: no cover - invoked by Docker
            print(f"[ready-check] http failure on port {args.http_port}: {exc}", file=sys.stderr)
            return 1

    http_note = f", http:{args.http_port} ok" if args.http_port is not None else ""
    print(f"[ready-check] ok (revision {state['current_revision']} / {state['expected_revision']}){http_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
