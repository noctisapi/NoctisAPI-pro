from __future__ import annotations

import sys


def emit(line: str) -> None:
    """Write a pre-serialized JSON line to stdout with immediate flush."""
    try:
        sys.stdout.write(line)
        sys.stdout.flush()
    except Exception:
        pass
