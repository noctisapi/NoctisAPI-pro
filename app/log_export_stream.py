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

ACCESS_TOKEN_PREFIX = "nctx_at_"
REFRESH_TOKEN_PREFIX = "nctx_rt_"
TOKEN_PREFIX = ACCESS_TOKEN_PREFIX
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
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        name                     TEXT    NOT NULL,
        token_hash               TEXT    NOT NULL UNIQUE,
        access_token_hash        TEXT,
        access_token_expires_at  TEXT,
        refresh_token_hash       TEXT,
        refresh_token_expires_at TEXT,
        refresh_token_rotated_at TEXT,
        enabled                  INTEGER NOT NULL DEFAULT 1,
        created_at               TEXT    NOT NULL,
        last_used_at             TEXT,
        last_used_ip             TEXT,
        expires_at               TEXT
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
    _ensure_consumer_refresh_columns(conn)
    conn.commit()


def _ensure_consumer_refresh_columns(conn: sqlite3.Connection) -> None:
    """Best-effort schema upgrade for DBs created before refresh-token support."""
    try:
        existing = {
            row["name"] if isinstance(row, sqlite3.Row) else row[1]
            for row in conn.execute("PRAGMA table_info(log_stream_consumers)").fetchall()
        }
    except sqlite3.Error as exc:
        _logger.warning("log_export_stream: schema introspection failed: %s", exc)
        return
    for name, ddl_type in (
        ("access_token_hash", "TEXT"),
        ("access_token_expires_at", "TEXT"),
        ("refresh_token_hash", "TEXT"),
        ("refresh_token_expires_at", "TEXT"),
        ("refresh_token_rotated_at", "TEXT"),
    ):
        if name not in existing:
            try:
                conn.execute(f"ALTER TABLE log_stream_consumers ADD COLUMN {name} {ddl_type}")
            except sqlite3.Error as exc:
                _logger.warning("log_export_stream: failed adding column %s: %s", name, exc)
    for stmt in (
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_log_stream_consumers_access_token_hash
        ON log_stream_consumers(access_token_hash)
        WHERE access_token_hash IS NOT NULL
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_log_stream_consumers_refresh_token_hash
        ON log_stream_consumers(refresh_token_hash)
        WHERE refresh_token_hash IS NOT NULL
        """,
    ):
        try:
            conn.execute(stmt)
        except sqlite3.Error as exc:
            _logger.warning("log_export_stream: index DDL warning: %s", exc)


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


def _future_utc(seconds: int) -> str:
    return datetime.fromtimestamp(time.time() + max(1, seconds), tz=timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _env_seconds(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return default


def get_access_token_seconds() -> int:
    return _env_seconds("HP_LOG_EXPORT_ACCESS_TOKEN_SECONDS", 3600)


def get_refresh_token_seconds() -> int:
    return _env_seconds("HP_LOG_EXPORT_REFRESH_TOKEN_SECONDS", 90 * 86400)


def _is_iso_expired(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        exp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False


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
    return generate_access_token()


def _generate_prefixed_token(prefix: str) -> tuple[str, str]:
    token = prefix + secrets.token_bytes(_TOKEN_RANDOM_BYTES).hex()
    return token, _hash_token(token)


def generate_access_token() -> tuple[str, str]:
    return _generate_prefixed_token(ACCESS_TOKEN_PREFIX)


def generate_refresh_token() -> tuple[str, str]:
    return _generate_prefixed_token(REFRESH_TOKEN_PREFIX)


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
    access_token, access_token_hash = generate_access_token()
    refresh_token, refresh_token_hash = generate_refresh_token()
    access_expires_at = _future_utc(get_access_token_seconds())
    refresh_expires_at = _future_utc(get_refresh_token_seconds())
    now = _utc_now()
    conn.execute(
        """
        INSERT INTO log_stream_consumers(
            name, token_hash, access_token_hash, access_token_expires_at,
            refresh_token_hash, refresh_token_expires_at, refresh_token_rotated_at,
            enabled, created_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            name,
            access_token_hash,
            access_token_hash,
            access_expires_at,
            refresh_token_hash,
            refresh_expires_at,
            now,
            now,
            expires_at,
        ),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM log_stream_consumers WHERE access_token_hash=?", (access_token_hash,)
    ).fetchone()
    return {
        "consumer_id": row[0],
        "name": name,
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": get_access_token_seconds(),
        "access_token_expires_at": access_expires_at,
        "refresh_token_expires_at": refresh_expires_at,
        "created_at": now,
    }


def authenticate_consumer(
    conn: sqlite3.Connection, token: str
) -> Optional[dict]:
    """
    Validate *token* and return the consumer row as a dict, or None.

    Returns None (and does not raise) on any failure so the caller can
    return 404 without leaking whether auth succeeded.
    """
    if not token:
        return None
    token_hash = _hash_token(token)
    if not token.startswith(ACCESS_TOKEN_PREFIX):
        return None
    lookup_column = "access_token_hash"
    row = conn.execute(
        f"""
        SELECT id, name, enabled, expires_at, access_token_expires_at
        FROM log_stream_consumers
        WHERE {lookup_column}=?
        """,
        (token_hash,),
    ).fetchone()
    if row is None:
        return None
    if not row["enabled"]:
        return None
    if _is_iso_expired(row["expires_at"]):
        return None
    if _is_iso_expired(row["access_token_expires_at"]):
        return None
    return dict(row)


def refresh_consumer_tokens(conn: sqlite3.Connection, refresh_token: str) -> Optional[dict]:
    """
    Rotate a refresh token and issue a new short-lived access token.

    Returns plaintext tokens once, or None on any auth/expiry failure. The old
    refresh token is invalidated atomically by replacing its hash.
    """
    if not refresh_token or not refresh_token.startswith(REFRESH_TOKEN_PREFIX):
        return None
    refresh_hash = _hash_token(refresh_token)
    row = conn.execute(
        """
        SELECT id, name, enabled, expires_at, refresh_token_expires_at
        FROM log_stream_consumers
        WHERE refresh_token_hash=?
        """,
        (refresh_hash,),
    ).fetchone()
    if row is None or not row["enabled"]:
        return None
    if _is_iso_expired(row["expires_at"]) or _is_iso_expired(row["refresh_token_expires_at"]):
        return None

    access_token, access_hash = generate_access_token()
    new_refresh_token, new_refresh_hash = generate_refresh_token()
    now = _utc_now()
    access_expires_at = _future_utc(get_access_token_seconds())
    refresh_expires_at = _future_utc(get_refresh_token_seconds())
    cur = conn.execute(
        """
        UPDATE log_stream_consumers
        SET token_hash=?,
            access_token_hash=?,
            access_token_expires_at=?,
            refresh_token_hash=?,
            refresh_token_expires_at=?,
            refresh_token_rotated_at=?
        WHERE id=? AND refresh_token_hash=?
        """,
        (
            access_hash,
            access_hash,
            access_expires_at,
            new_refresh_hash,
            refresh_expires_at,
            now,
            row["id"],
            refresh_hash,
        ),
    )
    conn.commit()
    if cur.rowcount == 0:
        return None
    return {
        "consumer_id": row["id"],
        "name": row["name"],
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "expires_in": get_access_token_seconds(),
        "access_token_expires_at": access_expires_at,
        "refresh_token_expires_at": refresh_expires_at,
    }


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
    result = rotate_consumer_tokens(conn, consumer_id)
    return result["access_token"] if result else None


def rotate_consumer_tokens(conn: sqlite3.Connection, consumer_id: int) -> Optional[dict]:
    """Rotate both access and refresh tokens for a consumer."""
    access_token, access_hash = generate_access_token()
    refresh_token, refresh_hash = generate_refresh_token()
    now = _utc_now()
    access_expires_at = _future_utc(get_access_token_seconds())
    refresh_expires_at = _future_utc(get_refresh_token_seconds())
    cur = conn.execute(
        """
        UPDATE log_stream_consumers
        SET token_hash=?,
            access_token_hash=?,
            access_token_expires_at=?,
            refresh_token_hash=?,
            refresh_token_expires_at=?,
            refresh_token_rotated_at=?
        WHERE id=?
        """,
        (
            access_hash,
            access_hash,
            access_expires_at,
            refresh_hash,
            refresh_expires_at,
            now,
            consumer_id,
        ),
    )
    conn.commit()
    if cur.rowcount == 0:
        return None
    return {
        "consumer_id": consumer_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": get_access_token_seconds(),
        "access_token_expires_at": access_expires_at,
        "refresh_token_expires_at": refresh_expires_at,
    }


def list_consumers(conn: sqlite3.Connection) -> list[dict]:
    """Return all consumers. token_hash is NEVER included in the result."""
    rows = conn.execute(
        """
        SELECT id, name, enabled, created_at, last_used_at, last_used_ip, expires_at,
               access_token_expires_at, refresh_token_expires_at, refresh_token_rotated_at,
               refresh_token_hash IS NOT NULL AS has_refresh_token
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
    source_ip: Optional[str],
    country: Optional[str],
    trap_flags: list,
) -> dict:
    """
    Build a redacted export payload.

    Deliberately excludes: full headers, User-Agent, token values,
    request/response bodies.
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
        "source_ip": str(source_ip or "").strip(),
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
    source_ip: Optional[str],
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
            source_ip=source_ip,
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
