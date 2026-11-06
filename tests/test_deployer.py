"""NOC-035: private Managed PRO deployer CLI.

These tests exercise orchestration and safety boundaries without contacting
Terraform providers, Docker, a VPS, or Cloudflare.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _operator_fixture(tmp_path: Path, *, status: str = "active"):
    manifest_path = tmp_path / "deployment-manifest.json"
    manifest_path.write_text(json.dumps({
        "deployment_id": "deployment-1",
        "created_at": "2026-01-01T00:00:00Z",
        "schema_version": 1,
        "status": status,
        "customer_id": "acme-01",
        "region": "nbg1",
        "sizing": "cx22",
        "hp_public_host": "api.example.com",
        "hp_admin_host": "admin.example.com",
    }), encoding="utf-8")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    paths = deployer.DeploymentPaths(
        manifest=manifest_path,
        state_dir=state_dir,
        cloudflare_state=state_dir / "cloudflare.tfstate",
        hetzner_state=state_dir / "hetzner.tfstate",
    )
    paths.hetzner_state.write_text("{}", encoding="utf-8")
    config = _config(tmp_path, private_key=True)
    runner = MagicMock()
    return paths, config, runner


def test_operator_commands_have_no_secret_and_use_managed_compose(tmp_path):
    config = _config(tmp_path, private_key=True)
    upgrade_command = deployer._remote_upgrade_command("1.2.3", force=False)
    backup_command = deployer._remote_backup_command()
    resume_command = deployer._remote_resume_command(config, "203.0.113.10")

    assert "--expected-version 1.2.3" in upgrade_command
    assert "MANAGED_COMPOSE_FILE" in backup_command
    assert "docker compose" in resume_command
    assert "GIT_DEPLOY_TOKEN" not in upgrade_command
    assert "CLOUDFLARE_API_TOKEN" not in backup_command


def test_upgrade_requires_confirmation_and_records_success(tmp_path):
    paths, config, runner = _operator_fixture(tmp_path)
    runner.run.return_value = subprocess.CompletedProcess([], 0, "", "backup: ok")
    with patch("scripts.deployer._operator_context", return_value=(paths, json.loads(paths.manifest.read_text()), config, "203.0.113.10", runner)):
        with pytest.raises(deployer.DeployerError, match="--confirm"):
            deployer.upgrade_instance(
                manifest_path=paths.manifest, state_dir=paths.state_dir,
                ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
                accept_new_host_key=False, approved_version="1.2.3", confirm=False, force=False,
            )
        assert deployer.upgrade_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, approved_version="1.2.3", confirm=True, force=False,
        ) == 0

    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert manifest["status"] == "active"
    assert manifest["operation_history"][-1]["result"] == "succeeded"
    remote_command = runner.run.call_args.args[0][-1]
    assert "--expected-version 1.2.3" in remote_command


def test_suspend_and_resume_are_reversible_and_idempotent(tmp_path):
    paths, config, runner = _operator_fixture(tmp_path)
    runner.run.return_value = subprocess.CompletedProcess([], 0, "", "ok")
    def current_context(**_kwargs):
        return paths, json.loads(paths.manifest.read_text()), config, "203.0.113.10", runner

    with patch("scripts.deployer._operator_context", side_effect=current_context):
        assert deployer.suspend_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, confirm=True,
        ) == 0
        assert json.loads(paths.manifest.read_text())["status"] == "suspended"
        assert deployer.suspend_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, confirm=True,
        ) == 0
        assert deployer.resume_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, confirm=True,
        ) == 0

    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert manifest["status"] == "active"
    assert [entry["result"] for entry in manifest["operation_history"]] == ["succeeded", "noop", "succeeded"]


def test_teardown_requires_two_confirmation_gates(tmp_path):
    paths, config, runner = _operator_fixture(tmp_path)
    with pytest.raises(deployer.DeployerError, match="--confirm"):
        deployer.teardown_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, deployment_id="deployment-1",
            retention_dir=tmp_path / "retention", cloudflare_account_id="account-1",
            ssh_public_key_file=tmp_path / "missing.pub", ssh_allowed_cidrs=["203.0.113.4/32"],
            confirm=False, confirm_deletion=False,
        )
    with pytest.raises(deployer.DeployerError, match="--confirm-deletion"):
        deployer.teardown_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, deployment_id="deployment-1",
            retention_dir=tmp_path / "retention", cloudflare_account_id="account-1",
            ssh_public_key_file=tmp_path / "missing.pub", ssh_allowed_cidrs=["203.0.113.4/32"],
            confirm=True, confirm_deletion=False,
        )


def test_teardown_rejects_identifier_that_is_not_the_manifest_id(tmp_path):
    paths, config, runner = _operator_fixture(tmp_path)
    public_key = tmp_path / "id_ed25519.pub"
    public_key.write_text("ssh-ed25519 AAAA test", encoding="utf-8")
    context = (paths, json.loads(paths.manifest.read_text()), config, "203.0.113.10", runner)
    with patch("scripts.deployer._operator_context", return_value=context):
        with pytest.raises(deployer.DeployerError, match="exactly match"):
            deployer.teardown_instance(
                manifest_path=paths.manifest, state_dir=paths.state_dir,
                ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
                accept_new_host_key=False, deployment_id="wrong-id",
                retention_dir=tmp_path / "retention", cloudflare_account_id="account-1",
                ssh_public_key_file=public_key, ssh_allowed_cidrs=["203.0.113.4/32"],
                confirm=True, confirm_deletion=True,
            )


def test_teardown_records_success_only_after_empty_states(tmp_path, monkeypatch):
    paths, config, runner = _operator_fixture(tmp_path)
    public_key = tmp_path / "id_ed25519.pub"
    public_key.write_text("ssh-ed25519 AAAA test", encoding="utf-8")
    runner.run.return_value = subprocess.CompletedProcess([], 0, "", "ok")
    context = (paths, json.loads(paths.manifest.read_text()), config, "203.0.113.10", runner)
    monkeypatch.setenv("HCLOUD_TOKEN", "hcloud-token")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cloudflare-token")
    with patch("scripts.deployer._operator_context", return_value=context), \
         patch("scripts.deployer._export_retention"), \
         patch("scripts.deployer._terraform_init"), \
         patch("scripts.deployer._terraform_destroy_plan_apply") as destroy, \
         patch("scripts.deployer._terraform_state_is_empty"):
        assert deployer.teardown_instance(
            manifest_path=paths.manifest, state_dir=paths.state_dir,
            ssh_private_key=config.ssh_private_key, ssh_user=config.ssh_user,
            accept_new_host_key=False, deployment_id="deployment-1",
            retention_dir=tmp_path / "retention", cloudflare_account_id="account-1",
            ssh_public_key_file=public_key, ssh_allowed_cidrs=["203.0.113.4/32"],
            confirm=True, confirm_deletion=True,
        ) == 0

    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert manifest["status"] == "decommissioned"
    assert manifest["operation_history"][-1]["result"] == "succeeded"
    assert destroy.call_count == 2
    assert all("teardown-modules" in str(call.args[1]) for call in destroy.call_args_list)
    assert all("allow_destroy" not in call.args[3] for call in destroy.call_args_list)
