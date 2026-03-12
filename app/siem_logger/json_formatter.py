from __future__ import annotations

import json
from typing import Any


def to_json_line(event: dict[str, Any]) -> str:
    """Serialize event to a single-line JSON string terminated with newline."""
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
