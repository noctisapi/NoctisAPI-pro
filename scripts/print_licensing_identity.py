#!/usr/bin/env python
"""
Print the licensing identity tuple the app presents to the licensing server.

Run inside a container (recommended):
  python /app/scripts/print_licensing_identity.py
"""

from __future__ import annotations

import json
import os
import sys

# Allow running from the repo root without needing to pre-set PYTHONPATH.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from honey_licensing.client import compute_client_identity


def main() -> int:
    ident = compute_client_identity()
    print(json.dumps(ident, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
