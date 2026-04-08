# app/log_export_stream.py
"""
PRO feature: Log Export via Long Polling.

Provides:
- Encrypted secrets storage (system_secrets table, AES-256 via Fernet)
- Consumer token management (log_stream_consumers table)
- Export event store (export_events table)
- Event ingestion helper called from the request pipeline
- Event retrieval for long polling
- Retention cleanup
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional

_logger = logging.getLogger(__name__)

TOKEN_PREFIX = "nctx_ls_"
_TOKEN_RANDOM_BYTES = 32

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = [
    # General-purpose encrypted key/value store. Values are Fernet-encrypted.
    """
    CREATE TABLE IF NOT EXISTS system_secrets (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL UNIQUE,
        encrypted_value TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
    """,
    # Consumer identities authorised to pull log exports.
    """
    CREATE TABLE IF NOT EXISTS log_stream_consumers (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        token_hash   TEXT    NOT NULL UNIQUE,
        enabled      INTEGER NOT NULL DEFAULT 1,
        created_at   TEXT    NOT NULL,
        last_used_at TEXT,
        last_used_ip TEXT,
        expires_at   TEXT
    )
    """,
    # Redacted, export-safe event records.  cursor IS the rowid.
    """
    CREATE TABLE IF NOT EXISTS export_events (
        cursor       INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id     TEXT NOT NULL UNIQUE,
        created_at   TEXT NOT NULL,
        event_type   TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        instance_id  TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_export_events_created_at ON export_events(created_at)",
]


def ensure_tables(conn: sqlite3.Connection) -> None:
    """Idempotently create log-export tables. Safe to call multiple times."""
    for stmt in _DDL:
        try:
            conn.execute(stmt)
        except sqlite3.Error as exc:
            _logger.warning("log_export_stream: DDL warning: %s", exc)
    conn.commit()


# ---------------------------------------------------------------------------
# Encryption (Fernet / AES-256-CBC + HMAC-SHA256)
# ---------------------------------------------------------------------------

_FERNET_INSTANCE: object = None  # lazily built


def _fernet() -> object:
    """Return a Fernet instance, lazily constructed from HP_SEED."""
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is not None:
        return _FERNET_INSTANCE

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise RuntimeError("cryptography package is required for log_export_stream")

    raw_key_env = (os.getenv("HP_SECRETS_KEY") or "").strip()
    if raw_key_env:
        # Accept a pre-generated Fernet key supplied via env (recommended for production).
        try:
            key = raw_key_env.encode()
            # Validate that it is a proper Fernet key (32-byte urlsafe-base64).
            base64.urlsafe_b64decode(key + b"==")
        except Exception:
            _logger.warning(
                "log_export_stream: HP_SECRETS_KEY is not a valid Fernet key; "
                "falling back to HP_SEED-derived key"
            )
            raw_key_env = ""

    if not raw_key_env:
        seed = (os.getenv("HP_SEED") or "CHANGE_ME_LONG_RANDOM_SEED").encode()
        raw = hashlib.sha256(seed + b":log_export_secrets_v1").digest()
        key = base64.urlsafe_b64encode(raw)

    _FERNET_INSTANCE = Fernet(key)
    return _FERNET_INSTANCE


def _reset_fernet_cache() -> None:
    """For tests only."""
    global _FERNET_INSTANCE
    _FERNET_INSTANCE = None


def encrypt_secret(plaintext: str) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 ciphertext string."""
    token = _fernet().encrypt(plaintext.encode())
    return token.decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a ciphertext produced by :func:`encrypt_secret`."""
    return _fernet().decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# system_secrets CRUD
# ---------------------------------------------------------------------------

def store_secret(conn: sqlite3.Connection, name: str, value: str) -> None:
    """Upsert an encrypted secret by *name*."""
    now = _utc_now()
    encrypted = encrypt_secret(value)
    conn.execute(
        """
        INSERT INTO system_secrets(name, encrypted_value, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET encrypted_value=excluded.encrypted_value, updated_at=excluded.updated_at
        """,
        (name, encrypted, now, now),
    )


def get_secret(conn: sqlite3.Connection, name: str) -> Optional[str]:
    """Return the decrypted value for *name*, or None if not found."""
    row = conn.execute(
        "SELECT encrypted_value FROM system_secrets WHERE name=?", (name,)
    ).fetchone()
    if row is None:
        return None
    try:
        return decrypt_secret(row[0])
    except Exception as exc:
        _logger.error("log_export_stream: failed to decrypt secret '%s': %s", name, exc)
        return None


# ---------------------------------------------------------------------------
# Token generation and hashing
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of *token*. This is what is stored in the DB."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_consumer_token() -> tuple[str, str]:
    """
    Generate a new consumer token.

    Returns ``(plaintext_token, token_hash)``.
    Only the hash is ever persisted.  The plaintext must be shown to the
    operator exactly once and then discarded.
    """
    raw = secrets.token_bytes(_TOKEN_RANDOM_BYTES)
    token = TOKEN_PREFIX + raw.hex()
    token_hash = _hash_token(token)
    return token, token_hash


# ---------------------------------------------------------------------------
# Consumer management
# ---------------------------------------------------------------------------

def create_consumer(
    conn: sqlite3.Connection,
    name: str,
    expires_at: Optional[str] = None,
) -> dict:
    """
    Create a new log-stream consumer.

    Returns a dict with ``consumer_id`` and the plaintext ``token`` (shown once).
    Caller must display the token to the operator; it is never retrievable again.
    """
    token, token_hash = generate_consumer_token()
    now = _utc_now()
    conn.execute(
        """
        INSERT INTO log_stream_consumers(name, token_hash, enabled, created_at, expires_at)
        VALUES (?, ?, 1, ?, ?)
        """,
        (name, token_hash, now, expires_at),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM log_stream_consumers WHERE token_hash=?", (token_hash,)
    ).fetchone()
    return {"consumer_id": row[0], "name": name, "token": token, "created_at": now}


def authenticate_consumer(
    conn: sqlite3.Connection, token: str
) -> Optional[dict]:
    """
    Validate *token* and return the consumer row as a dict, or None.

    Returns None (and does not raise) on any failure so the caller can
    return 404 without leaking whether auth succeeded.
    """
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    token_hash = _hash_token(token)
    row = conn.execute(
        """
        SELECT id, name, enabled, expires_at
        FROM log_stream_consumers
        WHERE token_hash=?
        """,
        (token_hash,),
    ).fetchone()
    if row is None:
        return None
    if not row["enabled"]:
        return None
    if row["expires_at"]:
        try:
            exp = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                return None
        except Exception:
            pass
    return dict(row)


def update_last_used(conn: sqlite3.Connection, consumer_id: int, ip: str) -> None:
    """Record the timestamp and IP of the most recent successful use."""
    now = _utc_now()
    try:
        conn.execute(
            "UPDATE log_stream_consumers SET last_used_at=?, last_used_ip=? WHERE id=?",
            (now, ip, consumer_id),
        )
        conn.commit()
    except Exception as exc:
        _logger.debug("log_export_stream: update_last_used failed: %s", exc)


def revoke_consumer(conn: sqlite3.Connection, consumer_id: int) -> bool:
    """Disable a consumer by ID. Returns True if a row was modified."""
    cur = conn.execute(
        "UPDATE log_stream_consumers SET enabled=0 WHERE id=?", (consumer_id,)
    )
    conn.commit()
    return cur.rowcount > 0


def set_consumer_enabled(
    conn: sqlite3.Connection, consumer_id: int, enabled: bool
) -> bool:
    cur = conn.execute(
        "UPDATE log_stream_consumers SET enabled=? WHERE id=?",
        (1 if enabled else 0, consumer_id),
    )
    conn.commit()
    return cur.rowcount > 0


def rotate_consumer_token(conn: sqlite3.Connection, consumer_id: int) -> Optional[str]:
    """
    Generate a fresh token for *consumer_id*.

    Returns the new plaintext token (shown once) or None if the consumer
    was not found.
    """
    token, token_hash = generate_consumer_token()
    cur = conn.execute(
        "UPDATE log_stream_consumers SET token_hash=? WHERE id=?",
        (token_hash, consumer_id),
    )
    conn.commit()
    if cur.rowcount == 0:
        return None
    return token


def list_consumers(conn: sqlite3.Connection) -> list[dict]:
    """Return all consumers. token_hash is NEVER included in the result."""
    rows = conn.execute(
        """
        SELECT id, name, enabled, created_at, last_used_at, last_used_ip, expires_at
        FROM log_stream_consumers
        ORDER BY id
        """
    ).fetchall()
    return [dict(r) for r in rows]


def delete_consumer(conn: sqlite3.Connection, consumer_id: int) -> bool:
    cur = conn.execute(
        "DELETE FROM log_stream_consumers WHERE id=?", (consumer_id,)
    )
    conn.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------

_INSTANCE_ID: Optional[str] = None


def _get_instance_id() -> str:
    global _INSTANCE_ID
    if _INSTANCE_ID is None:
        _INSTANCE_ID = (
            os.getenv("HP_DEPLOYMENT_ID")
            or os.getenv("APP_INSTANCE_ID")
            or os.getenv("HOSTNAME")
            or "noctis-unknown"
        ).strip()
    return _INSTANCE_ID


_EXPORT_EVENT_TYPES = {
    # honeypot interactions
    "probe", "token_used", "unknown_token", "admin_secrets", "cloud_metadata",
    "backup_download", "backup_list", "infra_vault", "root_console", "root_shell",
    "console_exec", "upload_trap", "keys_issued", "internal_config",
    # auth events
    "auth_login", "auth_me", "auth_apikey", "auth_token_request",
    "admin_login_attempt", "admin_rotate",
    # recon
    "recon_openapi", "recon_env", "recon_config", "recon_security",
    # system
    "system_startup", "system_alert",
}

_REDACT_PATHS = {"/backup", "/vault", "/secrets", "/keys", "/internal"}


def _should_export(kind: str) -> bool:
    return kind in _EXPORT_EVENT_TYPES


def _build_export_payload(
    *,
    kind: str,
    method: str,
    path: str,
    status: int,
    latency_ms: int,
    actor_id: str,
    country: Optional[str],
    trap_flags: list,
) -> dict:
    """
    Build a redacted export payload.

    Deliberately excludes: full headers, User-Agent, token values,
    geographic precision beyond country code, request/response bodies.
    """
    actor_hash = None
    if actor_id:
        actor_hash = hashlib.sha256(actor_id.encode()).hexdigest()[:16]
    return {
        "event_type": kind,
        "method": method,
        "path": path,
        "status": status,
        "latency_ms": latency_ms,
        "actor_id_hash": actor_hash,
        "country": country,
        "trap_flags": trap_flags or [],
    }


def try_emit_export_event(
    conn: sqlite3.Connection,
    *,
    kind: str,
    method: str,
    path: str,
    status: int,
    latency_ms: int,
    actor_id: str,
    country: Optional[str],
    trap_flags: Optional[list],
) -> None:
    """
    Attempt to insert an export event. Silently drops on any error.

    Designed to be called inside the existing DB transaction in
    ``log_all_requests``; commits nothing by itself.
    """
    if not _should_export(kind):
        return
    try:
        event_id = "evt_" + secrets.token_hex(12)
        now = _utc_now()
        payload = _build_export_payload(
            kind=kind,
            method=method,
            path=path,
            status=status,
            latency_ms=latency_ms,
            actor_id=actor_id,
            country=country,
            trap_flags=trap_flags or [],
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO export_events(event_id, created_at, event_type, payload_json, instance_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event_id,
                now,
                kind,
                json.dumps(payload, ensure_ascii=False),
                _get_instance_id(),
            ),
        )
    except Exception as exc:
        _logger.debug("log_export_stream: emit failed (table may not exist yet): %s", exc)


# ---------------------------------------------------------------------------
# Event retrieval
# ---------------------------------------------------------------------------

def get_oldest_cursor(conn: sqlite3.Connection) -> Optional[int]:
    row = conn.execute("SELECT MIN(cursor) AS c FROM export_events").fetchone()
    if row and row["c"] is not None:
        return int(row["c"])
    return None


def cursor_is_expired(conn: sqlite3.Connection, cursor: int) -> bool:
    """
    Return True when *cursor* predates the oldest retained event.

    A cursor of 0 is always valid (means "give me everything from the start").
    """
    if cursor <= 0:
        return False
    oldest = get_oldest_cursor(conn)
    if oldest is None:
        return False
    return cursor < oldest


def get_events_after(
    conn: sqlite3.Connection, cursor: int, max_events: int = 100
) -> list[dict]:
    """Return up to *max_events* export events with cursor > *cursor*."""
    max_events = max(1, min(max_events, 500))
    rows = conn.execute(
        """
        SELECT cursor, event_id, created_at, event_type, payload_json, instance_id
        FROM export_events
        WHERE cursor > ?
        ORDER BY cursor ASC
        LIMIT ?
        """,
        (cursor, max_events),
    ).fetchall()
    result = []
    for r in rows:
        try:
            data = json.loads(r["payload_json"] or "{}")
        except Exception:
            data = {}
        result.append(
            {
                "cursor": r["cursor"],
                "event_id": r["event_id"],
                "timestamp": r["created_at"],
                "event_type": r["event_type"],
                "instance_id": r["instance_id"],
                "data": data,
            }
        )
    return result


# ---------------------------------------------------------------------------
# Retention cleanup
# ---------------------------------------------------------------------------

_DEFAULT_RETENTION_SECONDS = 72 * 3600  # 3 days


def get_retention_seconds() -> int:
    raw = (os.getenv("HP_LOG_EXPORT_RETENTION_SECONDS") or "").strip()
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return _DEFAULT_RETENTION_SECONDS


def cleanup_old_events(conn: sqlite3.Connection, retention_seconds: Optional[int] = None) -> int:
    """
    Delete export_events older than *retention_seconds*.

    Returns the number of rows deleted.
    """
    if retention_seconds is None:
        retention_seconds = get_retention_seconds()
    now_ts = time.time()
    cutoff_ts = now_ts - retention_seconds
    cutoff_dt = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc)
    cutoff_iso = cutoff_dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        cur = conn.execute(
            "DELETE FROM export_events WHERE created_at < ?", (cutoff_iso,)
        )
        conn.commit()
        deleted = cur.rowcount
        if deleted > 0:
            _logger.info("log_export_stream: retention cleanup deleted %d event(s)", deleted)
        return deleted
    except Exception as exc:
        _logger.warning("log_export_stream: retention cleanup failed: %s", exc)
        return 0


def start_retention_worker(db_factory, interval_seconds: int = 3600) -> None:
    """
    Start a daemon thread that runs retention cleanup every *interval_seconds*.

    *db_factory* is a zero-arg callable that returns an open sqlite3.Connection.
    """
    import threading

    def _worker() -> None:
        while True:
            time.sleep(interval_seconds)
            try:
                conn = db_factory()
                try:
                    cleanup_old_events(conn)
                finally:
                    conn.close()
            except Exception as exc:
                _logger.warning("log_export_stream: retention worker error: %s", exc)

    t = threading.Thread(target=_worker, daemon=True, name="log-export-retention")
    t.start()
    _logger.info(
        "log_export_stream: retention worker started (interval=%ds, retention=%ds)",
        interval_seconds,
        get_retention_seconds(),
    )


# ---------------------------------------------------------------------------
# Stats helper (admin panel)
# ---------------------------------------------------------------------------

def get_export_stats(conn: sqlite3.Connection) -> dict:
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM export_events").fetchone()["c"]
        oldest = conn.execute("SELECT MIN(created_at) AS t FROM export_events").fetchone()["t"]
        newest = conn.execute("SELECT MAX(created_at) AS t FROM export_events").fetchone()["t"]
        consumers = conn.execute(
            "SELECT COUNT(*) AS c FROM log_stream_consumers WHERE enabled=1"
        ).fetchone()["c"]
        return {
            "total_events": int(total or 0),
            "oldest_event": oldest,
            "newest_event": newest,
            "active_consumers": int(consumers or 0),
            "retention_seconds": get_retention_seconds(),
        }
    except Exception as exc:
        _logger.debug("log_export_stream: get_export_stats failed: %s", exc)
        return {}
