from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from typing import Any


_LOCK = threading.Lock()
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ALLOWED_KEYS = {
    "PRO_BACKEND_URL",
    "HP_LICENSE_REPORT_URL",
    "LICENSE_KEY",
    "HP_APP_VERSION",
    "HP_APP_ID",
    "INSTANCE_FINGERPRINT_SHA256",
}


def config_path() -> str:
    return (os.getenv("HP_LICENSE_RUNTIME_CONFIG_PATH") or "/var/lib/myapp/license_runtime_overrides.json").strip()


def _normalize_value(key: str, value: Any) -> str:
    out = str(value or "").strip()
    if not out:
        return ""
    if key in ("PRO_BACKEND_URL", "HP_LICENSE_REPORT_URL"):
        return out.rstrip("/")
    if key == "INSTANCE_FINGERPRINT_SHA256":
        lowered = out.lower()
        if not _HEX64_RE.match(lowered):
            raise ValueError("invalid_INSTANCE_FINGERPRINT_SHA256")
        return lowered
    return out


def _read_json(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_json(path: str, data: dict[str, Any]) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="license-overrides-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=True, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def load_overrides() -> dict[str, str]:
    path = config_path()
    if not path:
        return {}
    raw = _read_json(path)
    out: dict[str, str] = {}
    for key in _ALLOWED_KEYS:
        if key not in raw:
            continue
        try:
            val = _normalize_value(key, raw.get(key))
        except ValueError:
            continue
        if val:
            out[key] = val
    return out


def save_overrides(*, updates: dict[str, Any], clear_all: bool = False) -> dict[str, str]:
    path = config_path()
    if not path:
        raise ValueError("missing_runtime_config_path")

    with _LOCK:
        merged = {} if clear_all else dict(load_overrides())
        for key, raw in (updates or {}).items():
            if key not in _ALLOWED_KEYS:
                continue
            if raw is None:
                continue
            val = _normalize_value(key, raw)
            if not val:
                merged.pop(key, None)
            else:
                merged[key] = val
        _write_json(path, merged)
        return dict(merged)


def clear_overrides() -> None:
    path = config_path()
    if not path:
        return
    with _LOCK:
        try:
            os.remove(path)
        except FileNotFoundError:
            return
        except Exception:
            _write_json(path, {})


def get_effective(name: str, default: str = "") -> str:
    if name in _ALLOWED_KEYS:
        overrides = load_overrides()
        override = str(overrides.get(name) or "").strip()
        if override:
            return override

    env_raw = os.getenv(name)
    if env_raw is None:
        return default
    env_val = str(env_raw).strip()
    if not env_val:
        return default
    if name in ("PRO_BACKEND_URL", "HP_LICENSE_REPORT_URL"):
        return env_val.rstrip("/")
    return env_val
