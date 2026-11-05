# app/panel_rbac.py
"""Backend RBAC for the admin console (NOC-019).

Defines the owner/admin/analyst/viewer role hierarchy and an explicit,
auditable permission matrix mapping every panel route (method + path) to
the minimum role required to call it. Enforced centrally in
app.panel_mvp._PanelRBACMiddleware -- not left to the frontend, and not
opt-in per handler, so a new route that is never added to the matrix below
fails closed (denied to everyone except OWNER) rather than silently open.

Role philosophy (each role includes everything the ones below it can do):
  VIEWER  -- read-only: dashboards, lists, detail pages.
  ANALYST -- VIEWER + the investigation workflow: case/actor triage
             (create/rename/status/evidence/archive), campaign recompute,
             and data EXPORT (treated as its own, higher-than-read tier --
             exporting enables bulk takeaway that plain viewing doesn't).
  ADMIN   -- ANALYST + instance configuration (endpoints, mutation, rules,
             environment settings), irreversible deletes (actor purge,
             campaign delete), and license status/refresh.
  OWNER   -- ADMIN + anything that issues or revokes access/credentials for
             another principal: license upload (changes the instance's
             commercial entitlement), log-export consumer tokens, and (from
             NOC-020 onward) other panel user accounts.

CF_ACCESS/HP_PANEL session auth already establishes *who* is calling
(app.panel_mvp._PanelAuthMiddleware, NOC-018); this module only answers
*what that person's role allows*.
"""
from __future__ import annotations

import re
from enum import IntEnum
from typing import List, Optional, Pattern, Tuple


class Role(IntEnum):
    VIEWER = 0
    ANALYST = 1
    ADMIN = 2
    OWNER = 3

    @classmethod
    def from_str(cls, value: str) -> "Role":
        try:
            return cls[value.strip().upper()]
        except (KeyError, AttributeError):
            raise ValueError(f"unknown role: {value!r}")


VALID_ROLES = tuple(r.name.lower() for r in Role)
DEFAULT_ROLE = Role.VIEWER.name.lower()


def has_permission(user_role: Optional[str], required: Role) -> bool:
    """True if *user_role* meets or exceeds *required*. Fails closed (False)
    for a missing, unknown, or malformed role -- never raises."""
    if not user_role:
        return False
    try:
        return Role.from_str(user_role) >= required
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Permission matrix: every panel route this app serves, explicitly.
#
# A path segment written as {name} matches exactly one path segment of any
# value (mirrors FastAPI's own path params -- this module re-derives the
# match itself since the ASGI middleware that enforces it runs before
# FastAPI's router resolves the route).
# ---------------------------------------------------------------------------

_V, _A, _AD, _O = Role.VIEWER, Role.ANALYST, Role.ADMIN, Role.OWNER

# (method, path_template, minimum_role)
ROUTE_RULES: List[Tuple[str, str, Role]] = [
    # Licensing
    ("GET", "/dashboard/license", _V),  # redirect only, nothing disclosed
    ("GET", "/admin/license", _O),  # internal debug snapshot incl. identity
    ("GET", "/dashboard/license/online-status", _AD),
    ("POST", "/dashboard/license/refresh", _AD),
    ("GET", "/dashboard/license/config", _AD),
    ("POST", "/dashboard/license/config", _AD),
    ("POST", "/dashboard/license/upload", _O),  # changes commercial entitlement
    # Honeypot availability / classification monitoring
    ("GET", "/dashboard/honeypot", _V),
    ("GET", "/admin/health/honeypot", _V),
    ("POST", "/admin/health/honeypot/recheck", _A),
    ("GET", "/admin/health/honeypot/history", _V),
    ("GET", "/admin/classification/summary", _V),
    ("POST", "/admin/classification/backfill", _AD),  # bulk data mutation
    # Dashboard home / api-modular
    ("GET", "/", _V),
    ("GET", "/dashboard", _V),
    ("GET", "/dashboard/api-modular", _V),
    ("GET", "/dashboard/api-modular/state", _V),
    ("GET", "/dashboard/api-modular/state-v2", _V),
    ("GET", "/dashboard/api-modular/catalog", _V),
    ("POST", "/dashboard/api-modular/custom-template/save", _AD),
    ("POST", "/dashboard/api-modular/custom-template/delete", _AD),
    ("POST", "/dashboard/api-modular/instance-config/save", _AD),
    ("POST", "/dashboard/api-modular/config", _AD),
    ("POST", "/dashboard/api-modular/config/delete", _AD),
    ("POST", "/dashboard/api-modular/template/apply", _AD),
    ("POST", "/dashboard/api-modular/mutation", _AD),
    ("POST", "/dashboard/api-modular/rules", _AD),
    ("POST", "/dashboard/api-modular/rules/delete", _AD),
    ("GET", "/dashboard/api-modular/analytics", _V),
    ("GET", "/dashboard/api-modular/resolve", _V),
    # Actors / cases investigation workflow
    ("GET", "/dashboard/actors", _V),
    ("GET", "/dashboard/cases", _V),
    ("GET", "/dashboard/cases/{case_id}", _V),
    ("POST", "/dashboard/cases", _A),
    ("POST", "/dashboard/cases/{case_id}/rename", _A),
    ("POST", "/dashboard/cases/{case_id}/status", _A),
    ("POST", "/dashboard/cases/{case_id}/campaign", _A),
    ("POST", "/dashboard/cases/{case_id}/actors", _A),
    ("POST", "/dashboard/cases/{case_id}/actors/remove", _A),
    ("POST", "/dashboard/cases/{case_id}/evidence", _A),
    ("POST", "/dashboard/cases/{case_id}/evidence/remove", _A),
    ("GET", "/dashboard/actor_add_case/{actor_id}", _V),
    ("POST", "/dashboard/cases/quick", _A),
    ("DELETE", "/dashboard/cases/{case_id}", _A),
    ("GET", "/dashboard/cases/{case_id}/export.json", _A),  # export tier
    ("GET", "/dashboard/cases/{case_id}/export.md", _A),
    ("POST", "/dashboard/actors/{actor_id}/archive", _A),
    ("POST", "/dashboard/actors/{actor_id}/unarchive", _A),
    ("POST", "/dashboard/actors/{actor_id}/trash", _A),
    ("POST", "/dashboard/actors/{actor_id}/restore", _A),
    ("POST", "/dashboard/actors/{actor_id}/purge", _AD),  # irreversible
    ("POST", "/dashboard/actors/purge_bulk", _AD),  # irreversible
    ("GET", "/dashboard/actors/deleted", _V),
    ("GET", "/dashboard/actors/{actor_id}/sessions", _V),
    ("GET", "/dashboard/sessions/{session_id}", _V),
    ("GET", "/dashboard/sessions/{session_id}/_legacy", _V),
    # Campaigns
    ("POST", "/dashboard/campaigns/recompute", _A),
    ("GET", "/dashboard/campaigns/recompute/status", _V),
    ("GET", "/dashboard/campaigns", _V),
    ("GET", "/dashboard/alerts", _V),
    ("GET", "/dashboard/debug/db", _AD),
    ("GET", "/dashboard/campaigns/{campaign_id}", _V),
    ("GET", "/dashboard/campaigns/{campaign_id}/export.json", _A),  # export tier
    ("GET", "/dashboard/campaigns/{campaign_id}/export.md", _A),
    ("DELETE", "/dashboard/campaigns/{campaign_id}", _AD),
    ("GET", "/dashboard/actors/{actor_id}/campaign", _V),
    ("GET", "/actor/{actor_id}", _V),
    # Environment / system settings
    ("GET", "/dashboard/environment", _AD),
    ("POST", "/dashboard/environment/settings", _AD),
    ("POST", "/dashboard/environment/diagnostics", _AD),
    # Replay
    ("GET", "/dashboard/replay", _V),
    ("GET", "/dashboard/replay/{session_id}", _V),
    ("GET", "/api/replay/{session_id}", _V),
    ("GET", "/api/replay/{session_id}/export/ndjson", _A),  # export tier
    ("GET", "/api/replay/{session_id}/export/har", _A),
    # Log export (PRO): consumer tokens are credentials for an external system
    ("GET", "/dashboard/log-export", _AD),
    ("GET", "/pro/log-export/stats", _AD),
    ("GET", "/pro/log-export/consumers", _AD),
    ("POST", "/pro/log-export/consumers", _O),  # issues a plaintext token
    ("POST", "/pro/log-export/consumers/{consumer_id}/revoke", _O),
    ("POST", "/pro/log-export/consumers/{consumer_id}/rotate", _O),
    ("GET", "/pro/log-export/agent.py", _AD),
    ("POST", "/pro/log-export/agent-bundle.zip", _AD),
    ("PUT", "/pro/log-export/consumers/{consumer_id}", _O),
    ("DELETE", "/pro/log-export/consumers/{consumer_id}", _O),
    # FastAPI's auto-generated OpenAPI/docs routes -- read-only API surface
    # documentation, same sensitivity as any other dashboard view.
    ("GET", "/openapi.json", _V),
    ("GET", "/docs", _V),
    ("GET", "/docs/oauth2-redirect", _V),
    ("GET", "/redoc", _V),
    # Member management (NOC-020): who else has access is visible to
    # admins, but inviting/revoking/re-roling other accounts is the same
    # "issues or revokes access for another principal" tier as license
    # upload and log-export consumer tokens above -- OWNER only.
    ("GET", "/dashboard/members", _AD),
    # Administrative audit log (NOC-021): coarse-grained, never contains a
    # secret by construction (method+path+status only) -- same visibility
    # tier as Members.
    ("GET", "/dashboard/audit-log", _AD),
    ("POST", "/dashboard/members/invite", _O),
    ("POST", "/dashboard/members/{user_id}/role", _O),
    ("POST", "/dashboard/members/{user_id}/deactivate", _O),
    ("POST", "/dashboard/members/{user_id}/activate", _O),
    ("POST", "/dashboard/members/{user_id}/revoke-sessions", _O),
]

# Routes _PanelAuthMiddleware already lets through with no session at all
# (see app.panel_mvp._PANEL_AUTH_BYPASS) -- RBAC does not apply to them
# either; listed here only so this module is a complete map of every route.
UNAUTHENTICATED_ROUTES = {
    ("GET", "/login"),
    ("POST", "/login"),
    ("POST", "/logout"),
    ("GET", "/reset-password"),
    ("POST", "/reset-password"),
    ("GET", "/health"),
    ("GET", "/ready"),
}

# Anything not matched above (a route added later and never classified)
# fails closed to the highest tier -- denied to everyone except OWNER.
DEFAULT_REQUIRED_ROLE = Role.OWNER

def _build_matcher(template: str) -> Pattern[str]:
    """Compile a route template ("/foo/{id}/bar") into a regex matching any
    concrete path FastAPI would route there, one path segment per {param}."""
    escaped = re.sub(
        r"\{[^/{}]+\}|[^{}]+",
        lambda m: "[^/]+" if m.group(0).startswith("{") else re.escape(m.group(0)),
        template,
    )
    return re.compile("^" + escaped + "$")


_COMPILED_RULES: List[Tuple[str, Pattern[str], Role]] = [
    (method, _build_matcher(template), role) for method, template, role in ROUTE_RULES
]


def required_role_for(method: str, path: str) -> Role:
    """Minimum role required to call *method* *path*, or DEFAULT_REQUIRED_ROLE
    (OWNER) if the route isn't in the matrix -- fail closed."""
    method = method.upper()
    for rule_method, pattern, role in _COMPILED_RULES:
        if rule_method == method and pattern.match(path):
            return role
    return DEFAULT_REQUIRED_ROLE
