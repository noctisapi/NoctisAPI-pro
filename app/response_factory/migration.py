"""Guardrails for progressive ResponseFactory rollout.

The factory is intentionally enabled only for endpoint_ids that have been
validated for contract parity and safe scoring behaviour.

Two migration sets exist:

  MIGRATED_ENDPOINT_IDS        — middleware-level interception (try_factory_response).
                                  Only safe for side-effect-free endpoints where
                                  call_next is bypassed entirely.

  HANDLER_MIGRATED_ENDPOINT_IDS — handler-assisted interception (try_handler_factory_response).
                                  Safe for endpoints that run side effects first
                                  (scoring, event recording) then delegate body
                                  generation to the factory.
"""
from __future__ import annotations

from typing import Optional


# Middleware-level batch: recon surfaces are read-only; no side effects skipped.
# `recon_openapi` is intentionally excluded because `/openapi.json` must always
# reflect the live modular runtime surface, not a factory-generated decoy.
MIGRATED_ENDPOINT_IDS: frozenset[str] = frozenset(
    {
        "recon_env",
        "recon_config",
    }
)

# Handler-assisted batch: side effects run inside the handler first; factory
# only generates the HTTP body.  Add endpoint_ids here once the handler has
# been updated to call try_handler_factory_response().
HANDLER_MIGRATED_ENDPOINT_IDS: frozenset[str] = frozenset(
    {
        "auth_register",
        "users_list",
        "users_get",
        "users_update",
        "orders_list",
        "orders_get",
        "orders_create",
    }
)


def is_migrated_endpoint(endpoint_id: Optional[str]) -> bool:
    return str(endpoint_id or "") in MIGRATED_ENDPOINT_IDS


def is_handler_migrated_endpoint(endpoint_id: Optional[str]) -> bool:
    return str(endpoint_id or "") in HANDLER_MIGRATED_ENDPOINT_IDS
