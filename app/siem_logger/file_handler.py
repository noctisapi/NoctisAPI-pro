from __future__ import annotations

import os
import threading

_lock = threading.Lock()
_path: str = ""


def configure(path: str) -> None:
    global _path
    _path = str(path or "").strip()
    if _path:
        try:
            os.makedirs(os.path.dirname(_path) or ".", exist_ok=True)
        except Exception:
            pass


def emit(line: str) -> None:
    """Append a JSON line to the log file (thread-safe)."""
    if not _path:
        return
    with _lock:
        try:
            with open(_path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        except Exception:
            pass
