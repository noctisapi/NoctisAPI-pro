"""NOC-035: private Managed PRO deployer CLI.

These tests exercise orchestration and safety boundaries without contacting
Terraform providers, Docker, a VPS, or Cloudflare.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import deployer
from scripts import deployment_manifest as manifest_lib


def _config(tmp_path: Path, *, private_key: bool = False) -> deployer.DeploymentConfig:
    private = tmp_path / "id_ed25519" if private_key else None
    if private:
        private.write_text("private-key-placeholder", encoding="utf-8")
    return deployer.DeploymentConfig(
        customer_id="acme-01",
        region="nbg1",
        sizing="cx22",
        public_host="api.example.com",
        admin_host="admin.example.com",
        acme_email="ops@example.com",
        app_version="1.2.3",
        ssh_public_key="ssh-ed25519 AAAA test",
        ssh_private_key=private,
        ssh_user="noctisops",
        ssh_allowed_cidrs=["203.0.113.4/32"],
        cloudflare_account_id="account-1",
        access_allowed_emails=["ops@example.com"],
    )


def test_prepare_manifest_is_stable_and_starts_provisioning(tmp_path):
    path = tmp_path / "deployment-manifest.json"
    config = _config(tmp_path)

    first = deployer._prepare_manifest(path, config, persist=True)
    second = deployer._prepare_manifest(path, config, persist=True)

    assert first["deployment_id"] == second["deployment_id"]
    assert second["status"] == manifest_lib.DeploymentStatus.PROVISIONING.value
    assert second["hp_public_host"] == "api.example.com"
    assert json.loads(path.read_text(encoding="utf-8"))["deployment_id"] == first["deployment_id"]


def test_tf_var_args_uses_hcl_boolean_and_json_lists():
    args = deployer._tf_var_args({"enable_access_application": False, "access_allowed_emails": ["ops@example.com"]})
    assert args == [
        "-var", "enable_access_application=false",
        "-var", 'access_allowed_emails=["ops@example.com"]',
    ]


def test_remote_commands_contain_no_credentials(tmp_path):
    config = _config(tmp_path, private_key=True)
    verify_command = deployer._remote_verify_command(config, "203.0.113.10", "203.0.113.10")
    assert "GIT_DEPLOY_TOKEN" not in verify_command
    assert "CLOUDFLARE" not in verify_command
    assert "203.0.113.10" in verify_command


def test_dry_run_validates_both_modules_without_persisting_manifest(tmp_path):
    config = _config(tmp_path)
    manifest = tmp_path / "manifest.json"
    with patch("scripts.deployer._terraform_init") as init:
        assert deployer.deploy(config, manifest_path=manifest, state_dir=None, dry_run=True) == 0
    assert init.call_count == 2
    assert not manifest.exists()


def test_deploy_failure_is_recorded_and_secret_is_redacted(tmp_path, monkeypatch, capsys):
    config = _config(tmp_path)
    manifest = tmp_path / "manifest.json"
    secret = "git-token-that-must-not-leak"
    monkeypatch.setenv("HCLOUD_TOKEN", "hcloud-token")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cloudflare-token")
    monkeypatch.setenv("GIT_DEPLOY_TOKEN", secret)

    with patch("scripts.deployer._terraform_init", side_effect=deployer.DeployerError(secret)):
        with pytest.raises(deployer.DeployerError) as exc_info:
            deployer.deploy(config, manifest_path=manifest, state_dir=None)

    assert secret not in str(exc_info.value)
    saved = json.loads(manifest.read_text(encoding="utf-8"))
    assert saved["status"] == manifest_lib.DeploymentStatus.FAILED.value
    assert secret not in capsys.readouterr().out
