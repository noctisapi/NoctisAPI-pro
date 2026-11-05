# app/panel_auth.py
"""Individual panel user identity and sessions (NOC-018).

Replaces the shared HP_PANEL_TOKEN-as-password login with per-installation
user accounts and DB-backed, individually revocable sessions. Stateless
HMAC session tokens (the previous mechanism) cannot be revoked before their
natural expiry; these are opaque random tokens whose SHA-256 hash is looked
up in panel_sessions on every request, so deleting/marking a row ends that
session immediately.

Only the hash of a session or password-reset token is ever persisted --
mirrors the existing log_export_stream.py token pattern. Passwords are
hashed with hashlib.scrypt (stdlib, memory-hard, no new dependency).

Provisioning (creating the first/other users) and recovery (issuing a
password-reset link) are operator-driven via scripts/panel_user.py for now
-- there is no self-service invite flow or SMTP integration yet; that
member-management UI is NOC-020's job, built on top of these primitives.
Role/permission enforcement is NOC-019's job.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional

PANEL_SESSION_TTL_SECONDS = 8 * 3600  # 8 hours
PASSWORD_RESET_TTL_SECONDS = 3600  # 1 hour
_TOKEN_RANDOM_BYTES = 32

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS panel_users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    NOT NULL UNIQUE,
        password_hash TEXT    NOT NULL,
        is_active     INTEGER NOT NULL DEFAULT 1,
        created_at    TEXT    NOT NULL,
        last_login_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS panel_sessions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER NOT NULL,
        token_hash   TEXT    NOT NULL UNIQUE,
        created_at   TEXT    NOT NULL,
        expires_at   TEXT    NOT NULL,
        revoked_at   TEXT,
        last_seen_at TEXT,
        ip_address   TEXT,
        user_agent   TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_panel_sessions_user_id ON panel_sessions(user_id)",
    """
    CREATE TABLE IF NOT EXISTS panel_password_resets (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        token_hash TEXT    NOT NULL UNIQUE,
        created_at TEXT    NOT NULL,
        expires_at TEXT    NOT NULL,
        used_at    TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_panel_password_resets_user_id ON panel_password_resets(user_id)",
]


def ensure_tables(conn: sqlite3.Connection) -> None:
    """Idempotently create panel identity/session tables. Safe to call repeatedly."""
    for stmt in _DDL:
        conn.execute(stmt)
    conn.commit()


# ---------------------------------------------------------------------------
# Time helpers (mirrors app/log_export_stream.py)
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _future_utc(seconds: int) -> str:
    return (
        datetime.fromtimestamp(time.time() + max(1, seconds), tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _is_iso_expired(value: Optional[str], *, now: Optional[float] = None) -> bool:
    if not value:
        return True
    try:
        exp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return True
    current = datetime.fromtimestamp(now, tz=timezone.utc) if now is not None else datetime.now(timezone.utc)
    return current > exp


# ---------------------------------------------------------------------------
# Password hashing (hashlib.scrypt -- memory-hard, stdlib only)
# ---------------------------------------------------------------------------

_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n_str, r_str, p_str, salt_b64, digest_b64 = stored.split("$", 5)
        if algo != "scrypt":
            return False
        n, r, p = int(n_str), int(r_str), int(p_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except Exception:
        return False
    candidate = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected)
    )
    return secrets.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# Opaque token generation/hashing (mirrors app/log_export_stream.py)
# ---------------------------------------------------------------------------


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token() -> str:
    return secrets.token_bytes(_TOKEN_RANDOM_BYTES).hex()


def derive_csrf_token(raw_session_token: str) -> str:
    """Deterministic double-submit CSRF token derived from a session token.

    The session token lives only in an httponly cookie, so a cross-site
    attacker can neither read it nor compute this value -- no separate
    server-side secret or extra DB column is needed.
    """
    return hashlib.sha256((raw_session_token + ":csrf").encode()).hexdigest()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


class UsernameTakenError(Exception):
    pass


def create_user(conn: sqlite3.Connection, username: str, password: str, *, is_active: bool = True) -> int:
    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")
    if not password:
        raise ValueError("password must not be empty")
    try:
        cur = conn.execute(
            "INSERT INTO panel_users(username, password_hash, is_active, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), 1 if is_active else 0, _utc_now()),
        )
    except sqlite3.IntegrityError as exc:
        raise UsernameTakenError(username) from exc
    conn.commit()
    return int(cur.lastrowid)


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT * FROM panel_users WHERE username = ?", (username.strip(),)
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM panel_users WHERE id = ?", (user_id,)).fetchone()


def list_users(conn: sqlite3.Connection) -> list:
    conn.row_factory = sqlite3.Row
    return list(conn.execute("SELECT * FROM panel_users ORDER BY username").fetchall())


def count_users(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM panel_users").fetchone()
    return int(row[0]) if row else 0


def set_user_active(conn: sqlite3.Connection, user_id: int, active: bool) -> None:
    conn.execute("UPDATE panel_users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))
    conn.commit()
    if not active:
        revoke_all_sessions_for_user(conn, user_id)


def update_password(conn: sqlite3.Connection, user_id: int, new_password: str) -> None:
    conn.execute(
        "UPDATE panel_users SET password_hash = ? WHERE id = ?",
        (hash_password(new_password), user_id),
    )
    conn.commit()


def _touch_last_login(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE panel_users SET last_login_at = ? WHERE id = ?", (_utc_now(), user_id))
    conn.commit()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def create_session(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    ttl_seconds: int = PANEL_SESSION_TTL_SECONDS,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    raw = _generate_token()
    conn.execute(
        """
        INSERT INTO panel_sessions(user_id, token_hash, created_at, expires_at, last_seen_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, _hash_token(raw), _utc_now(), _future_utc(ttl_seconds), _utc_now(), ip_address, (user_agent or "")[:256]),
    )
    conn.commit()
    _touch_last_login(conn, user_id)
    return raw


def verify_session(conn: sqlite3.Connection, raw_token: str) -> Optional[sqlite3.Row]:
    """Return the owning (active) user row for a valid, unexpired, unrevoked
    session token, or None. Refreshes last_seen_at on success."""
    if not raw_token:
        return None
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT s.id AS session_id, s.expires_at, s.revoked_at,
               u.id AS id, u.username AS username, u.is_active AS is_active
        FROM panel_sessions s
        JOIN panel_users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (_hash_token(raw_token),),
    ).fetchone()
    if not row:
        return None
    if row["revoked_at"] or not row["is_active"] or _is_iso_expired(row["expires_at"]):
        return None
    conn.execute(
        "UPDATE panel_sessions SET last_seen_at = ? WHERE id = ?", (_utc_now(), row["session_id"])
    )
    conn.commit()
    return row


def revoke_session(conn: sqlite3.Connection, raw_token: str) -> None:
    conn.execute(
        "UPDATE panel_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        (_utc_now(), _hash_token(raw_token)),
    )
    conn.commit()


def revoke_all_sessions_for_user(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE panel_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (_utc_now(), user_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Password reset ("recuperación de acceso")
# ---------------------------------------------------------------------------


def create_password_reset(
    conn: sqlite3.Connection, user_id: int, *, ttl_seconds: int = PASSWORD_RESET_TTL_SECONDS
) -> str:
    raw = _generate_token()
    conn.execute(
        "INSERT INTO panel_password_resets(user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, _hash_token(raw), _utc_now(), _future_utc(ttl_seconds)),
    )
    conn.commit()
    return raw


def consume_password_reset(conn: sqlite3.Connection, raw_token: str, new_password: str) -> bool:
    """Validate a one-time reset token and set the new password. Revokes all
    of that user's existing sessions (a password reset should end every
    session started with the old, possibly-compromised password)."""
    if not raw_token:
        return False
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM panel_password_resets WHERE token_hash = ?", (_hash_token(raw_token),)
    ).fetchone()
    if not row or row["used_at"] or _is_iso_expired(row["expires_at"]):
        return False
    update_password(conn, row["user_id"], new_password)
    conn.execute(
        "UPDATE panel_password_resets SET used_at = ? WHERE id = ?", (_utc_now(), row["id"])
    )
    conn.commit()
    revoke_all_sessions_for_user(conn, row["user_id"])
    return True
