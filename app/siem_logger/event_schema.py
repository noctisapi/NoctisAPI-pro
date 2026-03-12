from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

# Maps honeypot event kinds → (attack_type, MITRE ATT&CK TTP)
_KIND_MAP: dict[str, tuple[str, str]] = {
    "probe":           ("recon",                "T1595"),
    "recon_docs":      ("api_recon",            "T1592"),
    "recon_openapi":   ("api_recon",            "T1592"),
    "recon_swagger":   ("api_recon",            "T1592"),
    "recon_redoc":     ("api_recon",            "T1592"),
    "recon_env":       ("config_discovery",     "T1592.002"),
    "recon_config":    ("config_discovery",     "T1592.002"),
    "recon_security":  ("config_discovery",     "T1592.002"),
    "token_used":      ("credential_use",       "T1078"),
    "unknown_token":   ("brute_force",          "T1110"),
    "keys_issued":     ("credential_access",    "T1649"),
    "internal_config": ("internal_recon",       "T1592"),
    "backup_list":     ("data_discovery",       "T1530"),
    "backup_download": ("data_exfiltration",    "T1530"),
    "admin_secrets":   ("privilege_escalation", "T1078.004"),
    "infra_vault":     ("privilege_escalation", "T1078.004"),
    "cloud_metadata":  ("cloud_metadata_access","T1552.005"),
    "root_console":    ("privilege_escalation", "T1078.003"),
    "health":          ("availability_probe",   "T1595"),
}

_DEFAULT_ATTACK = ("recon", "T1595")


def make_event(
    *,
    kind: str,
    source_ip: str,
    method: str,
    endpoint: str,
    status_code: int,
    user_agent: str,
    interaction_id: str,
    actor_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> dict:
    """Return a normalized SIEM security event dict."""
    attack_type, ttp = _KIND_MAP.get(str(kind or "probe"), _DEFAULT_ATTACK)
    sc = int(status_code or 0)
    return {
        "timestamp":      datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "event_type":     "api_attack" if sc >= 400 else "api_interaction",
        "source_ip":      str(source_ip or ""),
        "method":         str(method or "").upper(),
        "endpoint":       str(endpoint or "/"),
        "status_code":    sc,
        "user_agent":     str(user_agent or "")[:400],
        "attack_type":    attack_type,
        "ttp":            ttp,
        "interaction_id": str(interaction_id or ""),
        "actor_id":       str(actor_id) if actor_id else None,
        "session_id":     str(session_id) if session_id else None,
    }
