"""NOC-031: scripts/deployment_manifest.py -- schema, state machine, and
validation for compose/secrets/deployment-manifest.json. Pure tmp_path
tests, no Docker/network, same convention as test_init_deployment.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.deployment_manifest as dm  # noqa: E402


class TestStampSchema:
    def test_fills_in_missing_fields(self):
        manifest = {"deployment_id": "abc"}
        dm.stamp_schema(manifest)
        assert manifest["schema_version"] == dm.SCHEMA_VERSION
        assert manifest["status"] == "active"

    def test_does_not_overwrite_existing_status(self):
        manifest = {"deployment_id": "abc", "status": "provisioning"}
        dm.stamp_schema(manifest)
        assert manifest["status"] == "provisioning"


class TestValidateTransition:
    def test_provisioning_to_active_is_valid(self):
        dm.validate_transition(dm.DeploymentStatus.PROVISIONING, dm.DeploymentStatus.ACTIVE)  # no raise

    def test_active_to_decommissioned_directly_is_invalid(self):
        with pytest.raises(dm.InvalidTransition):
            dm.validate_transition(dm.DeploymentStatus.ACTIVE, dm.DeploymentStatus.DECOMMISSIONED)

    def test_decommissioned_is_terminal(self):
        for target in dm.DeploymentStatus:
            if target == dm.DeploymentStatus.DECOMMISSIONED:
                continue
            with pytest.raises(dm.InvalidTransition):
                dm.validate_transition(dm.DeploymentStatus.DECOMMISSIONED, target)

    def test_self_transition_is_always_allowed(self):
        for status in dm.DeploymentStatus:
            dm.validate_transition(status, status)  # no raise, including DECOMMISSIONED -> DECOMMISSIONED

    def test_failed_can_retry_to_provisioning_or_active(self):
        dm.validate_transition(dm.DeploymentStatus.FAILED, dm.DeploymentStatus.PROVISIONING)
        dm.validate_transition(dm.DeploymentStatus.FAILED, dm.DeploymentStatus.ACTIVE)


class TestSetStatus:
    def test_first_ever_status_set_needs_no_transition_check(self):
        manifest = {"deployment_id": "abc"}
        dm.set_status(manifest, dm.DeploymentStatus.PROVISIONING, now="2026-01-01T00:00:00Z")
        assert manifest["status"] == "provisioning"
        assert manifest["status_history"][0]["from"] is None
        assert manifest["status_history"][0]["to"] == "provisioning"

    def test_valid_transition_updates_status_and_history(self):
        manifest = {"deployment_id": "abc", "status": "provisioning"}
        dm.set_status(manifest, dm.DeploymentStatus.ACTIVE, reason="bootstrap complete", now="2026-01-02T00:00:00Z")
        assert manifest["status"] == "active"
        entry = manifest["status_history"][-1]
        assert entry == {
            "timestamp": "2026-01-02T00:00:00Z", "from": "provisioning", "to": "active", "reason": "bootstrap complete",
        }

    def test_invalid_transition_raises_and_does_not_mutate(self):
        manifest = {"deployment_id": "abc", "status": "active"}
        try:
            dm.set_status(manifest, dm.DeploymentStatus.DECOMMISSIONED, now="2026-01-01T00:00:00Z")
            assert False, "expected InvalidTransition"
        except dm.InvalidTransition:
            pass
        assert manifest["status"] == "active"  # unchanged
        assert "status_history" not in manifest

    def test_history_is_capped_at_20(self):
        manifest = {"deployment_id": "abc", "status": "active"}
        for i in range(25):
            target = dm.DeploymentStatus.DEGRADED if i % 2 == 0 else dm.DeploymentStatus.ACTIVE
            dm.set_status(manifest, target, now=f"2026-01-{(i % 28) + 1:02d}T00:00:00Z")
        assert len(manifest["status_history"]) <= 20

    def test_idempotent_reset_to_same_status_does_not_raise(self):
        manifest = {"deployment_id": "abc", "status": "active"}
        dm.set_status(manifest, dm.DeploymentStatus.ACTIVE, now="2026-01-01T00:00:00Z")  # no raise
        assert manifest["status"] == "active"


class TestFindSensitiveKeys:
    def test_flat_secret_key_is_found(self):
        assert dm._find_sensitive_keys({"hp_seed": "x"}) == ["hp_seed"]

    def test_nested_secret_key_is_found(self):
        offenders = dm._find_sensitive_keys({"upgrade_history": [{"token": "x"}]})
        assert offenders == ["upgrade_history.token"]

    def test_clean_manifest_has_none(self):
        assert dm._find_sensitive_keys({"deployment_id": "abc", "customer_id": "acme"}) == []


class TestValidateManifest:
    def _valid(self):
        return {
            "deployment_id": "abc123",
            "created_at": "2026-01-01T00:00:00Z",
            "schema_version": 1,
            "status": "active",
        }

    def test_valid_manifest_has_no_errors(self):
        assert dm.validate_manifest(self._valid()) == []

    def test_missing_deployment_id_is_an_error(self):
        manifest = self._valid()
        del manifest["deployment_id"]
        errors = dm.validate_manifest(manifest)
        assert any("deployment_id" in e for e in errors)

    def test_missing_schema_version_is_an_error(self):
        manifest = self._valid()
        del manifest["schema_version"]
        errors = dm.validate_manifest(manifest)
        assert any("schema_version" in e for e in errors)

    def test_unsupported_schema_version_is_an_error(self):
        manifest = self._valid()
        manifest["schema_version"] = 99
        errors = dm.validate_manifest(manifest)
        assert any("schema_version" in e for e in errors)

    def test_invalid_status_is_an_error(self):
        manifest = self._valid()
        manifest["status"] = "not-a-real-status"
        errors = dm.validate_manifest(manifest)
        assert any("status" in e for e in errors)

    def test_wrong_type_field_is_an_error(self):
        manifest = self._valid()
        manifest["region"] = 12345
        errors = dm.validate_manifest(manifest)
        assert any("region" in e for e in errors)

    def test_secret_looking_key_is_an_error(self):
        manifest = self._valid()
        manifest["hp_seed"] = "leaked"
        errors = dm.validate_manifest(manifest)
        assert any("secret" in e.lower() for e in errors)

    def test_missing_created_at_is_an_error(self):
        manifest = self._valid()
        del manifest["created_at"]
        errors = dm.validate_manifest(manifest)
        assert any("created_at" in e for e in errors)


class TestCliMain:
    def _write(self, path, manifest):
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_validate_passes_on_a_good_manifest(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / "manifest.json"
        self._write(path, {
            "deployment_id": "abc", "created_at": "2026-01-01T00:00:00Z", "schema_version": 1, "status": "active",
        })
        monkeypatch.setattr(sys, "argv", ["deployment_manifest.py", "--manifest", str(path), "validate"])
        assert dm.main() == 0

    def test_validate_fails_on_a_bad_manifest(self, tmp_path, monkeypatch):
        path = tmp_path / "manifest.json"
        self._write(path, {"created_at": "2026-01-01T00:00:00Z"})
        monkeypatch.setattr(sys, "argv", ["deployment_manifest.py", "--manifest", str(path), "validate"])
        assert dm.main() == 1

    def test_set_status_writes_the_new_status(self, tmp_path, monkeypatch):
        path = tmp_path / "manifest.json"
        self._write(path, {"deployment_id": "abc", "created_at": "2026-01-01T00:00:00Z", "status": "provisioning"})
        monkeypatch.setattr(sys, "argv", ["deployment_manifest.py", "--manifest", str(path), "set-status", "active"])
        assert dm.main() == 0
        on_disk = json.loads(path.read_text())
        assert on_disk["status"] == "active"

    def test_set_status_rejects_an_invalid_transition(self, tmp_path, monkeypatch):
        path = tmp_path / "manifest.json"
        self._write(path, {"deployment_id": "abc", "created_at": "2026-01-01T00:00:00Z", "status": "active"})
        monkeypatch.setattr(
            sys, "argv", ["deployment_manifest.py", "--manifest", str(path), "set-status", "decommissioned"]
        )
        assert dm.main() == 1
        on_disk = json.loads(path.read_text())
        assert on_disk["status"] == "active"  # unchanged, write didn't happen
