from __future__ import annotations

import pytest

from app.panel_rbac import Role, required_role_for
from control_center.security import (
    ControlCenterAccessError,
    ControlCenterPrincipal,
    audit_event,
    authorize,
)


def test_control_center_requires_an_authenticated_principal() -> None:
    with pytest.raises(ControlCenterAccessError):
        authorize("GET", "/control-center", None)


def test_control_center_reads_use_existing_role_matrix() -> None:
    principal = ControlCenterPrincipal("operator-1", "viewer", "session")
    assert authorize("GET", "/control-center", principal) == principal
    assert required_role_for("GET", "/control-center") == Role.VIEWER


def test_control_center_mutations_require_mfa_and_admin_role() -> None:
    session_admin = ControlCenterPrincipal("operator-1", "admin", "session")
    with pytest.raises(ControlCenterAccessError):
        authorize("POST", "/control-center/jobs", session_admin)

    mfa_viewer = ControlCenterPrincipal("operator-1", "viewer", "sso_mfa")
    with pytest.raises(ControlCenterAccessError):
        authorize("POST", "/control-center/jobs", mfa_viewer)

    mfa_admin = ControlCenterPrincipal("operator-1", "admin", "sso_mfa")
    assert authorize("POST", "/control-center/jobs", mfa_admin) == mfa_admin


def test_audit_event_redacts_credentials_recursively() -> None:
    principal = ControlCenterPrincipal("operator-1", "admin", "sso_mfa")
    event = audit_event(
        principal=principal,
        action="job_requested",
        entity_type="deployment",
        entity_id="dep-1",
        details={
            "provider": "hetzner",
            "token": "do-not-store",
            "nested": {"password": "also-do-not-store"},
        },
    )
    assert event["details"]["provider"] == "hetzner"
    assert event["details"]["token"] == "[REDACTED]"
    assert event["details"]["nested"]["password"] == "[REDACTED]"
