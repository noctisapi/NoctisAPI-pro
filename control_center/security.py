"""Authentication and audit contracts for Control Center requests.

The existing panel middleware establishes the session and RBAC role.  This
module adds the stronger assurance required for Control Center mutations
without putting credentials in browser code or in the Control Center data
model.  SSO/MFA adapters can later map their provider claims to
``authn_level`` without changing these authorization rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping

from app.panel_rbac import Role, has_permission, required_role_for

AUTHN_LEVELS = ("session", "sso", "mfa", "sso_mfa")
MFA_LEVELS = frozenset(("mfa", "sso_mfa"))
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "password",
        "password_hash",
        "secret",
        "token",
        "api_key",
        "access_token",
        "refresh_token",
        "private_key",
    }
)


@dataclass(frozen=True)
class ControlCenterPrincipal:
    """Identity projected by the authenticated panel/SSO layer."""

    subject: str
    role: str
    authn_level: str = "session"
    customer_scope: tuple[str, ...] = ()


class ControlCenterAccessError(PermissionError):
    """Raised when a request does not meet Control Center policy."""


def _is_mutation(method: str) -> bool:
    return method.upper() not in {"GET", "HEAD", "OPTIONS"}


def _required_role(method: str, path: str) -> Role:
    """Resolve the existing fail-closed RBAC matrix for Control Center paths."""

    return required_role_for(method, path)


def authorize(
    method: str,
    path: str,
    principal: ControlCenterPrincipal | None,
) -> ControlCenterPrincipal:
    """Authorize a Control Center request, failing closed for missing identity."""

    if principal is None or not principal.subject.strip():
        raise ControlCenterAccessError("authenticated operator required")
    if principal.authn_level not in AUTHN_LEVELS:
        raise ControlCenterAccessError("unknown authentication assurance level")
    if not has_permission(principal.role, _required_role(method, path)):
        raise ControlCenterAccessError("operator role is insufficient")
    if _is_mutation(method) and principal.authn_level not in MFA_LEVELS:
        raise ControlCenterAccessError("MFA assurance required for Control Center mutations")
    return principal


def sanitize_audit_details(value: Any) -> Any:
    """Return JSON-shaped audit details with credential-like fields removed."""

    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _SENSITIVE_KEYS else sanitize_audit_details(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def audit_event(
    *,
    principal: ControlCenterPrincipal,
    action: str,
    entity_type: str,
    entity_id: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an auditable event without persisting secrets or request bodies."""

    return {
        "actor_ref": principal.subject,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "details": sanitize_audit_details(details or {}),
    }
