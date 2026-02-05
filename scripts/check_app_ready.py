#!/usr/bin/env python
"""Container healthcheck for the internal application state."""
import sys

from app import status_checks


def main() -> int:
    try:
        state = status_checks.ensure_ready()
    except Exception as exc:  # pragma: no cover - invoked by Docker
        print(f"[ready-check] failure: {exc}", file=sys.stderr)
        return 1
    print(
        f"[ready-check] ok (revision {state['current_revision']} / {state['expected_revision']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
