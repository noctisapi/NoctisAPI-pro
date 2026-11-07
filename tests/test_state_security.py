"""NOC-038 security contracts; no cloud provider or infrastructure required."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from scripts.state_security import (
    AwsSecretsManager,
    StateBackendConfig,
    StateSecurityError,
    secret_manager_from_env,
)


def test_real_backend_requires_explicit_remote_configuration(monkeypatch):
    monkeypatch.delenv("NOCTISAPI_TF_STATE_BACKEND", raising=False)
    monkeypatch.delenv("NOCTISAPI_TF_STATE_BUCKET", raising=False)
    with pytest.raises(StateSecurityError, match="NOCTISAPI_TF_STATE_BUCKET"):
        StateBackendConfig.from_env()


def test_local_backend_is_rejected_without_explicit_test_permission(monkeypatch):
    monkeypatch.setenv("NOCTISAPI_TF_STATE_BACKEND", "local")
    with pytest.raises(StateSecurityError, match="local Terraform state"):
        StateBackendConfig.from_env()
    assert StateBackendConfig.from_env(allow_local=True).backend == "local"


def test_s3_backend_is_tenant_scoped_and_encrypted(monkeypatch):
    monkeypatch.setenv("NOCTISAPI_TF_STATE_BACKEND", "s3")
    monkeypatch.setenv("NOCTISAPI_TF_STATE_BUCKET", "noctisapi-tf-state")
    monkeypatch.setenv("NOCTISAPI_TF_STATE_REGION", "eu-west-1")
    monkeypatch.setenv("NOCTISAPI_TF_STATE_LOCK_TABLE", "noctisapi-tf-lock")
    config = StateBackendConfig.from_env()

    assert config.key_for("hetzner", "customer-1", "deployment-1") == (
        "noctisapi/customer-1/deployment-1/hetzner.tfstate"
    )
    args = config.init_args("cloudflare", "customer-1", "deployment-1")
    assert "-backend-config=encrypt=true" in args
    assert "-backend-config=dynamodb_table=noctisapi-tf-lock" in args
    assert "customer-1" in " ".join(args)


def test_state_endpoint_must_be_tls(monkeypatch):
    for key, value in {
        "NOCTISAPI_TF_STATE_BACKEND": "s3",
        "NOCTISAPI_TF_STATE_BUCKET": "state",
        "NOCTISAPI_TF_STATE_REGION": "eu-west-1",
        "NOCTISAPI_TF_STATE_LOCK_TABLE": "locks",
        "NOCTISAPI_TF_STATE_ENDPOINT": "http://minio.invalid",
    }.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(StateSecurityError, match="https"):
        StateBackendConfig.from_env()


def test_environment_secret_store_is_test_only(monkeypatch):
    monkeypatch.setenv("NOCTISAPI_SECRET_BACKEND", "env")
    monkeypatch.setenv("TEST_SECRET", "value")
    with pytest.raises(StateSecurityError, match="test-only"):
        secret_manager_from_env()
    assert secret_manager_from_env(allow_environment=True).get("TEST_SECRET") == "value"


def test_aws_secret_manager_never_places_secret_value_in_argv():
    manager = AwsSecretsManager(prefix="noctisapi/test", region="eu-west-1")
    with patch("scripts.state_security.subprocess.run") as run:
        run.return_value = type("Result", (), {"returncode": 0, "stdout": '"secret-value"'})()
        assert manager.get("HCLOUD_TOKEN") == "secret-value"
        args = run.call_args.args[0]
        assert "secret-value" not in args
        manager.rotate("HCLOUD_TOKEN")
        rotate_args = run.call_args.args[0]
        assert "secret-value" not in rotate_args
