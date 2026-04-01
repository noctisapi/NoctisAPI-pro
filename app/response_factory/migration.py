"""Guardrails for progressive ResponseFactory rollout.

The factory is intentionally enabled only for endpoint_ids that have been
validated for contract parity and safe scoring behaviour.
"""
from __future__ import annotations

from typing import Optional


# First coherent migrated batch:
# - Recon surfaces are read-only
# - middleware already synthesises the legacy hp_event kinds for them
# - no token/session/secret side effects are skipped when call_next is bypassed
MIGRATED_ENDPOINT_IDS: frozenset[str] = frozenset(
    {
        "recon_env",
        "recon_config",
        "recon_openapi",
    }
)


def is_migrated_endpoint(endpoint_id: Optional[str]) -> bool:
    return str(endpoint_id or "") in MIGRATED_ENDPOINT_IDS
