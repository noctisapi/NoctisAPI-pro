"""FlawApplicator — modifies generated payloads to simulate vulnerability behaviors.

DESIGN PRINCIPLE:
  Flaw application is a POST-PROCESSING step on an already-generated payload.
  It NEVER generates a payload from scratch. It modifies what the generators produce.

  This keeps the two layers separate:
    generators.py    → "what a normal response looks like"
    flaw_applicator  → "what breaks in this response"

FLAW BEHAVIORS:

  IDOR (idor_basic / idor_advanced):
    - Replaces some id fields with a neighboring id (off-by-N)
    - Optionally exposes an owner_id / user_id field (advanced)
    - Signals a cross-user data leak

  SQLI_HINT (sqli_hint_basic):
    - With configurable probability, wraps the payload in an error dict
      containing a SQL fragment in the message
    - Only fires on 2xx responses

  PATH_TRAVERSAL (path_traversal_basic):
    - If operation_type is FILE_DOWNLOAD or OBJECT_READ, replaces body
      with content of a fake "sensitive file"
    - Only fires when payload contains no error

  BROKEN_AUTH (broken_auth_basic):
    - Adds a "auth_note" field hinting that credentials were not validated
    - Does NOT change status code (let factory decide that)

  EXCESSIVE_DATA (excessive_data_basic):
    - Appends extra sensitive fields to user/order/auth response objects:
      password_hash, internal_notes, api_key_preview

No DB access. Pure function on payload dict.
"""
from __future__ import annotations

import random
from typing import Any, Optional

from app.catalog.types import FlawKind, OperationType
from app.runtime.models import EffectiveFlaw


# ── IDOR ──────────────────────────────────────────────────────────────────────

def _apply_idor(
    payload: Any,
    flaw: EffectiveFlaw,
    rng: random.Random,
    operation_type: OperationType,
) -> tuple[Any, bool]:
    """Mutate id fields to simulate IDOR. Returns (mutated_payload, fired)."""
    if not isinstance(payload, dict):
        return payload, False

    params = flaw.parameters
    leak_prob = float(params.get("leak_probability", 0.6))
    id_range = params.get("id_offset_range", [1, 5])
    expose_owner = bool(params.get("expose_owner_field", False))

    if rng.random() > leak_prob:
        return payload, False

    out = dict(payload)
    offset = rng.randint(int(id_range[0]), int(id_range[1]))

    # Shift any id field that looks like a numeric or prefixed id
    for key in ("id", "order_id", "user_id", "customer_id"):
        if key in out:
            val = out[key]
            if isinstance(val, str) and "_" in val:
                # "ord_abc123" → increment numeric suffix
                prefix, _, suffix = val.rpartition("_")
                try:
                    new_suffix = format(int(suffix, 16) + offset, "x") if all(c in "0123456789abcdef" for c in suffix) else suffix
                except ValueError:
                    new_suffix = suffix
                out[key] = f"{prefix}_{new_suffix}"

    if expose_owner and "user_id" not in out and "customer_id" in out:
        out["owner_id"] = out["customer_id"]

    return out, True


# ── SQLi hint ────────────────────────────────────────────────────────────────

_SQLI_FRAGMENTS = [
    "ERROR: column \"users.password_hash\" does not exist",
    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    "ORA-00942: table or view does not exist",
    "Unclosed quotation mark after the character string",
    "ERROR: invalid input syntax for type integer: \"'\"",
]

_DB_TYPES = {
    "mysql": "mysql",
    "postgres": "postgresql",
    "oracle": "oracle",
    "mssql": "mssql",
}


def _apply_sqli_hint(
    payload: Any,
    flaw: EffectiveFlaw,
    rng: random.Random,
    status_code: int,
) -> tuple[Any, bool]:
    """Wrap payload in an error containing a SQL fragment."""
    if status_code >= 400:
        return payload, False  # error responses already convey something
    params = flaw.parameters
    prob = float(params.get("hint_probability", 0.4))
    if rng.random() > prob:
        return payload, False
    fragment = rng.choice(_SQLI_FRAGMENTS)
    db_type = params.get("db_type", "mysql")
    mutated = {
        "error": "Database error",
        "detail": fragment,
        "db_type": db_type,
        "original": payload if isinstance(payload, dict) else None,
    }
    return mutated, True


# ── Path traversal ────────────────────────────────────────────────────────────

_FAKE_FILE_CONTENTS: dict[str, str] = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\napp:x:1000:1000::/home/app:/bin/bash",
    "/etc/hostname": "prod-api-01",
    "/proc/version": "Linux version 5.15.0-1034-aws (buildd@lcy02-amd64-009) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #38-Ubuntu SMP",
}


def _apply_path_traversal(
    payload: Any,
    flaw: EffectiveFlaw,
    rng: random.Random,
    operation_type: OperationType,
) -> tuple[Any, bool]:
    if operation_type not in (OperationType.FILE_DOWNLOAD, OperationType.OBJECT_READ):
        return payload, False
    params = flaw.parameters
    prob = float(params.get("success_probability", 0.7))
    if rng.random() > prob:
        return payload, False
    files = params.get("accessible_files", list(_FAKE_FILE_CONTENTS.keys()))
    chosen = rng.choice(files)
    content = _FAKE_FILE_CONTENTS.get(chosen, f"# contents of {chosen}\nplaceholder")
    return content, True


# ── Broken auth ───────────────────────────────────────────────────────────────

def _apply_broken_auth(
    payload: Any,
    flaw: EffectiveFlaw,
    rng: random.Random,
) -> tuple[Any, bool]:
    if not isinstance(payload, dict):
        return payload, False
    out = dict(payload)
    # Subtle hint that auth was skipped
    out["_auth"] = "ok"  # as if token was validated without checking
    return out, True


# ── Excessive data exposure ───────────────────────────────────────────────────

def _apply_excessive_data(
    payload: Any,
    flaw: EffectiveFlaw,
    rng: random.Random,
) -> tuple[Any, bool]:
    if not isinstance(payload, dict):
        return payload, False
    params = flaw.parameters
    prob = float(params.get("leak_probability", 0.8))
    if rng.random() > prob:
        return payload, False
    extra_fields = params.get("extra_fields", ["password_hash", "internal_notes", "api_key_preview"])
    out = dict(payload)
    for field in extra_fields:
        if field == "password_hash":
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"
            suffix = "".join(rng.choices(chars, k=53))
            out["password_hash"] = f"$2b$12${suffix}"
        elif field == "internal_notes":
            out["internal_notes"] = rng.choice([
                "Account flagged for review",
                "VIP customer, bypass rate limit",
                "DO NOT DELETE - legacy billing",
                "Migrated from old system",
            ])
        elif field == "api_key_preview":
            out["api_key_preview"] = f"sk_live_{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))}..."

    # Optionally expose user object extra fields
    if "user" in out and isinstance(out["user"], dict):
        if "password_hash" not in out["user"]:
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"
            suffix = "".join(rng.choices(chars, k=53))
            out["user"]["password_hash"] = f"$2b$12${suffix}"

    return out, True


# ── Main entry point ──────────────────────────────────────────────────────────

def apply_flaw(
    payload: Any,
    flaw: EffectiveFlaw,
    *,
    operation_type: OperationType,
    status_code: int,
    endpoint_id: str,
    salt: str = "",
) -> tuple[Any, bool, str]:
    """Apply a flaw behavior to a generated payload.

    Returns:
      (mutated_payload, flaw_fired, content_type_override)
      content_type_override is "" when the content type does not change.
    """
    import hashlib
    from datetime import datetime, timezone
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    seed_bytes = hashlib.sha256(f"flaw:{endpoint_id}:{day}:{salt}".encode()).digest()
    seed = int.from_bytes(seed_bytes[:8], "big")
    rng = random.Random(seed)

    content_type_override = ""

    if flaw.kind == FlawKind.IDOR:
        mutated, fired = _apply_idor(payload, flaw, rng, operation_type)
        return mutated, fired, content_type_override

    if flaw.kind == FlawKind.SQLI_HINT:
        mutated, fired = _apply_sqli_hint(payload, flaw, rng, status_code)
        return mutated, fired, content_type_override

    if flaw.kind == FlawKind.PATH_TRAVERSAL:
        mutated, fired = _apply_path_traversal(payload, flaw, rng, operation_type)
        if fired and isinstance(mutated, str):
            content_type_override = "text/plain"
        return mutated, fired, content_type_override

    if flaw.kind == FlawKind.BROKEN_AUTH:
        mutated, fired = _apply_broken_auth(payload, flaw, rng)
        return mutated, fired, content_type_override

    if flaw.kind == FlawKind.EXCESSIVE_DATA:
        mutated, fired = _apply_excessive_data(payload, flaw, rng)
        return mutated, fired, content_type_override

    # Unknown flaw kind: pass through unchanged
    return payload, False, content_type_override
