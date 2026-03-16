from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any


PRO_STATE_TABLE = "campaign_pro_state"
PRO_STATUS_VERIFIED = "verified"
PRO_STATUS_PENDING = "pending"
PRO_STATUS_UNVERIFIED = "unverified"

# ---------------------------------------------------------------------------
# Behavior patterns: maps pattern name → set of event kinds that signal it.
# Higher-severity patterns are listed first for priority resolution.
# ---------------------------------------------------------------------------
BEHAVIOR_PATTERNS: dict[str, frozenset[str]] = {
    "infrastructure_probing": frozenset({
        "infra_vault", "root_console", "internal_config", "admin_secrets",
    }),
    "data_exfiltration": frozenset({
        "backup_download", "backup_list", "cloud_metadata",
    }),
    "key_theft": frozenset({
        "keys_issued", "token_issued",
    }),
    "credential_harvesting": frozenset({
        "auth_login", "auth_mfa", "unknown_token", "token_used", "auth_token_request",
    }),
    "reconnaissance": frozenset({
        "probe", "recon_docs", "recon_openapi", "recon_swagger",
        "recon_redoc", "recon_env", "recon_config", "recon_security",
    }),
}

# Ordered from highest to lowest severity for tie-breaking
_BEHAVIOR_SEVERITY_ORDER = [
    "infrastructure_probing", "data_exfiltration", "key_theft",
    "credential_harvesting", "reconnaissance",
]

# Paths associated with recon/admin targets (for fallback classifier)
_RECON_PATH_FRAGMENTS = frozenset({
    "/docs", "/openapi", "/.env", "/config", "/.well-known",
    "/swagger", "/redoc", "/api-docs",
})
_ADMIN_PATH_FRAGMENTS = frozenset({
    "/admin", "/internal", "/root", "/backup", "/infra",
    "/cloud", "/vault", "/secret",
})

# UA version / build noise to strip before fingerprinting
_UA_VERSION_RE = re.compile(r"/[\d][.\d]*")
_UA_PAREN_RE = re.compile(r"\([^)]*\)")
_UA_WHITESPACE_RE = re.compile(r"\s+")


class CampaignProError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        val = int(default)
    else:
        try:
            val = int(raw.strip())
        except Exception:
            val = int(default)
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


def _env_float(name: str, default: float, min_value: float | None = None, max_value: float | None = None) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        val = float(default)
    else:
        try:
            val = float(raw.strip())
        except Exception:
            val = float(default)
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Signal extraction helpers
# ---------------------------------------------------------------------------

def normalize_ua_fingerprint(ua: str) -> str:
    """Return a stable, version-stripped fingerprint for a User-Agent string.

    Strips version numbers (``/1.2.3``), parenthesised build strings, and
    normalises whitespace.  If the result would exceed 120 chars it is replaced
    with its SHA-256 prefix so the fingerprint stays indexable.
    """
    if not ua:
        return ""
    cleaned = _UA_VERSION_RE.sub("", ua)
    cleaned = _UA_PAREN_RE.sub("", cleaned)
    cleaned = _UA_WHITESPACE_RE.sub(" ", cleaned).strip().lower()
    if not cleaned:
        return ""
    if len(cleaned) > 120:
        return hashlib.sha256(cleaned.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return cleaned


def extract_token_prefix(token: str) -> str:
    """Return a stable 8-char hex prefix-hash for a bearer/API token.

    Strips common scheme prefixes (``Bearer``, ``Token``) before hashing, so
    that the same credential encoded differently still maps to the same key.
    Returns empty string for blank or very short tokens.
    """
    if not token:
        return ""
    t = token.strip()
    for pfx in ("bearer ", "token ", "basic "):
        if t.lower().startswith(pfx):
            t = t[len(pfx):]
            break
    t = t.strip()
    if len(t) < 4:
        return ""
    return hashlib.sha256(t[:128].encode("utf-8", errors="ignore")).hexdigest()[:8]


def header_fingerprint(headers: dict[str, Any]) -> str:
    """Return a 12-char hex fingerprint for a set of HTTP headers.

    Only stable, non-session-specific headers are considered (Accept,
    Accept-Language, Accept-Encoding, Connection, Accept-Charset).  This lets
    us detect actors using the same HTTP client library across different IPs.
    """
    keys = [
        "accept", "accept-language", "accept-encoding",
        "accept-charset", "connection",
    ]
    parts = []
    for k in keys:
        v = headers.get(k) or headers.get(k.title()) or headers.get(k.upper()) or ""
        parts.append(f"{k}={str(v)}")
    sig = "|".join(parts)
    if not sig.replace("|", "").replace("=", "").strip():
        return ""
    return hashlib.sha256(sig.encode("utf-8", errors="ignore")).hexdigest()[:12]


def ip_subnet(ip: str) -> str:
    """Return the /16 subnet for an IPv4 address (first two octets).

    Returns empty string for IPv6 or invalid addresses.
    """
    if not ip or ":" in ip:
        return ""
    parts = ip.split(".")
    if len(parts) >= 2:
        try:
            int(parts[0]); int(parts[1])
            return f"{parts[0]}.{parts[1]}"
        except ValueError:
            pass
    return ""


# ---------------------------------------------------------------------------
# Behavior pattern classification
# ---------------------------------------------------------------------------

def classify_behavior_pattern(
    techniques: list[str],
    endpoints: list[str],
    feature_set: set[str],
) -> str:
    """Classify a campaign's dominant attack behaviour.

    Scoring priority (highest first):
    1. Count how many observed *technique* event kinds match each pattern.
    2. If tied or no technique match, fall back to endpoint path heuristics.
    3. If still undecided, use feature set path density.
    """
    pattern_scores: dict[str, int] = {}
    for pattern, signals in BEHAVIOR_PATTERNS.items():
        score = sum(1 for t in (techniques or []) if t in signals)
        if score:
            pattern_scores[pattern] = score

    if pattern_scores:
        top_score = max(pattern_scores.values())
        top_patterns = [p for p, s in pattern_scores.items() if s == top_score]
        # Resolve ties by severity
        for sv in _BEHAVIOR_SEVERITY_ORDER:
            if sv in top_patterns:
                return sv
        return top_patterns[0]

    # Endpoint path heuristic
    path_features = {f.split("::", 1)[1] for f in (feature_set or set()) if f.startswith("path::")}
    all_paths = set(path_features) | {str(e) for e in (endpoints or [])}

    recon_hits = sum(1 for p in all_paths if any(frag in p for frag in _RECON_PATH_FRAGMENTS))
    admin_hits = sum(1 for p in all_paths if any(frag in p for frag in _ADMIN_PATH_FRAGMENTS))

    if admin_hits >= 2 and admin_hits >= recon_hits:
        return "targeted_attack"
    if recon_hits >= 2 and recon_hits > admin_hits:
        return "reconnaissance"
    if len(all_paths) >= 12:
        return "broad_scanning"
    return "unknown"


# ---------------------------------------------------------------------------
# Scoring utilities
# ---------------------------------------------------------------------------

def stage_from_score(score: int) -> int:
    if score < 10:
        return 0
    if score < 20:
        return 1
    if score < 32:
        return 2
    if score < 48:
        return 3
    if score < 68:
        return 4
    if score < 92:
        return 5
    if score < 120:
        return 6
    if score < 155:
        return 7
    return 8


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex_obj(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def sha256_hex_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def campaign_config_from_env() -> dict[str, Any]:
    """Build the full campaign correlation configuration from environment vars.

    Feature-extraction parameters control *what* data is collected per actor.
    Signal-weight parameters control *how much* each signal type contributes to
    the weighted Jaccard similarity.  Changing weights does NOT invalidate the
    actor fingerprint cache; only feature-extraction parameters do.
    """
    return {
        # ── Feature extraction ──────────────────────────────────────────────
        "min_features": _env_int("HP_CAMPAIGN_MIN_FEATURES", 4, 1, 50),
        "min_intersection": _env_int("HP_CAMPAIGN_MIN_INTERSECTION", 3, 1, 50),
        "min_jaccard": _env_float("HP_CAMPAIGN_MIN_JACCARD", 0.4, 0.0, 1.0),
        "max_sessions": _env_int("HP_CAMPAIGN_MAX_SESSIONS", 5, 1, 20),
        "path_ngram_top_k": _env_int("HP_CAMPAIGN_PATH_NGRAM_TOP_K", 12, 1, 40),
        "path_top_k": _env_int("HP_CAMPAIGN_PATH_TOP_K", 10, 1, 40),
        "actor_limit": _env_int("HP_CAMPAIGN_ACTOR_LIMIT", 200, 10, 500),
        "max_steps_per_session": _env_int("HP_CAMPAIGN_MAX_STEPS_PER_SESSION", 200, 20, 500),
        "max_events_per_actor": _env_int("HP_CAMPAIGN_MAX_EVENTS_PER_ACTOR", 120, 20, 500),
        # ── Signal weights ──────────────────────────────────────────────────
        # Each weight multiplies the feature's contribution to the Jaccard
        # numerator and denominator.  Higher weight = stronger signal.
        "w_path": _env_float("HP_CAMPAIGN_W_PATH", 1.0, 0.0, 10.0),
        "w_stage": _env_float("HP_CAMPAIGN_W_STAGE", 1.5, 0.0, 10.0),
        "w_time": _env_float("HP_CAMPAIGN_W_TIME", 0.8, 0.0, 10.0),
        "w_err": _env_float("HP_CAMPAIGN_W_ERR", 1.2, 0.0, 10.0),
        "w_ua": _env_float("HP_CAMPAIGN_W_UA", 2.0, 0.0, 10.0),
        "w_geo": _env_float("HP_CAMPAIGN_W_GEO", 0.7, 0.0, 10.0),
        "w_tok": _env_float("HP_CAMPAIGN_W_TOK", 3.0, 0.0, 10.0),
        "w_hdr": _env_float("HP_CAMPAIGN_W_HDR", 1.3, 0.0, 10.0),
        "w_subnet": _env_float("HP_CAMPAIGN_W_SUBNET", 0.9, 0.0, 10.0),
    }


def campaign_cache_config_key(config: dict[str, Any]) -> dict[str, Any]:
    """Return the subset of *config* that determines which features are extracted.

    Signal weights do NOT affect what data is queried, so they are excluded
    from the cache validity key.  This prevents weight-only changes from
    invalidating all cached fingerprints.
    """
    extraction_keys = (
        "max_sessions", "path_ngram_top_k", "path_top_k",
        "max_steps_per_session", "max_events_per_actor",
    )
    return {k: config[k] for k in extraction_keys if k in config}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def ensure_campaign_pro_state_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {PRO_STATE_TABLE} (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.commit()


def upsert_campaign_pro_state(conn: sqlite3.Connection, values: dict[str, Any]) -> None:
    ensure_campaign_pro_state_table(conn)
    cur = conn.cursor()
    for key, value in values.items():
        cur.execute(
            f"INSERT OR REPLACE INTO {PRO_STATE_TABLE}(key, value) VALUES(?, ?)",
            (str(key), str(value)),
        )
    conn.commit()


def get_campaign_pro_state(conn: sqlite3.Connection) -> dict[str, str]:
    ensure_campaign_pro_state_table(conn)
    cur = conn.cursor()
    cur.execute(f"SELECT key, value FROM {PRO_STATE_TABLE}")
    return {str(r["key"]): str(r["value"]) for r in cur.fetchall()}


def mark_campaign_status(
    conn: sqlite3.Connection,
    *,
    status: str,
    reason: str = "",
    job_id: str = "",
    snapshot_hash: str = "",
    expires_at: int | None = None,
) -> None:
    payload: dict[str, Any] = {
        "status": status,
        "reason": reason or "",
        "job_id": job_id or "",
        "snapshot_hash": snapshot_hash or "",
        "updated_at": _utc_now_iso(),
    }
    payload["expires_at"] = int(expires_at) if expires_at is not None else 0
    upsert_campaign_pro_state(conn, payload)


def campaigns_status_summary(conn: sqlite3.Connection, backend_enabled: bool) -> dict[str, Any]:
    _ = backend_enabled
    state = get_campaign_pro_state(conn)
    status = state.get("status") or ""
    if status == PRO_STATUS_VERIFIED:
        out: dict[str, Any] = {
            "status": status,
            "verified": True,
            "message": "Resultado disponible",
        }
        try:
            exp = int(state.get("expires_at") or "0")
        except Exception:
            exp = 0
        if exp > 0:
            now = int(time.time())
            if exp <= now:
                return {
                    "status": PRO_STATUS_UNVERIFIED,
                    "verified": False,
                    "message": "Resultado no disponible (expirado)",
                }
            out["expires_at"] = exp
        return out
    if status == PRO_STATUS_PENDING:
        return {"status": status, "verified": False, "message": "Recompute en progreso"}
    if status == PRO_STATUS_UNVERIFIED:
        reason = state.get("reason") or "invalido"
        return {"status": status, "verified": False, "message": f"Resultado no disponible ({reason})"}
    return {"status": "none", "verified": False, "message": "Resultado no disponible"}


def can_render_verified_campaigns(conn: sqlite3.Connection, backend_enabled: bool) -> bool:
    summary = campaigns_status_summary(conn, backend_enabled=backend_enabled)
    return bool(summary.get("verified"))


def clear_campaign_tables(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("DELETE FROM campaign_actor_links")
    cur.execute("DELETE FROM campaigns")
    conn.commit()
