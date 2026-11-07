"""Security contracts for Managed Deployer state and secrets (NOC-038).

The deployer must not silently fall back to a local Terraform state in a real
operation.  The production contract is an encrypted S3-compatible backend
with DynamoDB locking, keyed by tenant and deployment id.  The environment
secret store is intentionally available only to tests and local dry-runs.

No provider is contacted by this module.  It validates configuration and
builds Terraform/AWS CLI arguments without ever placing a secret in argv.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, Optional


class StateSecurityError(RuntimeError):
    """A state or secret security contract is not satisfied."""


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise StateSecurityError(f"required NOC-038 configuration is missing: {name}")
    return value


@dataclass(frozen=True)
class StateBackendConfig:
    """Validated Terraform backend configuration.

    ``local`` exists only as an explicit test fixture.  A production caller
    must use ``s3`` and provide encryption plus a lock table.
    """

    backend: str
    bucket: str = ""
    region: str = ""
    lock_table: str = ""
    key_prefix: str = "noctisapi"
    endpoint: str = ""
    role_arn: str = ""

    @classmethod
    def local_for_tests(cls) -> "StateBackendConfig":
        return cls(backend="local")

    @classmethod
    def from_env(cls, *, allow_local: bool = False) -> "StateBackendConfig":
        requested = os.getenv("NOCTISAPI_TF_STATE_BACKEND", "").strip().lower()
        # A dry-run has no state side effects and should remain provider-free.
        # Real operations still default to the secure remote contract below.
        if allow_local and not requested:
            return cls.local_for_tests()
        backend = requested or "s3"
        if backend == "local":
            if not allow_local:
                raise StateSecurityError(
                    "local Terraform state is disabled for real operations; "
                    "configure NOCTISAPI_TF_STATE_BACKEND=s3"
                )
            return cls.local_for_tests()
        if backend != "s3":
            raise StateSecurityError("NOCTISAPI_TF_STATE_BACKEND must be 's3' or 'local'")

        config = cls(
            backend="s3",
            bucket=_required("NOCTISAPI_TF_STATE_BUCKET"),
            region=_required("NOCTISAPI_TF_STATE_REGION"),
            lock_table=_required("NOCTISAPI_TF_STATE_LOCK_TABLE"),
            key_prefix=os.getenv("NOCTISAPI_TF_STATE_PREFIX", "noctisapi").strip(),
            endpoint=os.getenv("NOCTISAPI_TF_STATE_ENDPOINT", "").strip(),
            role_arn=os.getenv("NOCTISAPI_TF_STATE_ROLE_ARN", "").strip(),
        )
        for label, value in (
            ("NOCTISAPI_TF_STATE_BUCKET", config.bucket),
            ("NOCTISAPI_TF_STATE_REGION", config.region),
            ("NOCTISAPI_TF_STATE_LOCK_TABLE", config.lock_table),
            ("NOCTISAPI_TF_STATE_PREFIX", config.key_prefix),
        ):
            if not value or not _SAFE_NAME.fullmatch(value):
                raise StateSecurityError(f"invalid {label}: use a bounded provider-safe name")
        if config.endpoint and not config.endpoint.startswith("https://"):
            raise StateSecurityError("NOCTISAPI_TF_STATE_ENDPOINT must use https://")
        if config.role_arn and not config.role_arn.startswith("arn:"):
            raise StateSecurityError("NOCTISAPI_TF_STATE_ROLE_ARN must be an ARN")
        return config

    def key_for(self, module: str, tenant_id: str, deployment_id: str) -> str:
        """Return a tenant-scoped, stable state key for one Terraform module."""
        for label, value in (("tenant_id", tenant_id), ("deployment_id", deployment_id)):
            if not value or not _SAFE_NAME.fullmatch(value):
                raise StateSecurityError(f"invalid {label} for Terraform state key")
        module_name = module.removeprefix("terraform-")
        if not _SAFE_NAME.fullmatch(module_name):
            raise StateSecurityError("invalid Terraform module name")
        return f"{self.key_prefix}/{tenant_id}/{deployment_id}/{module_name}.tfstate"

    def init_args(self, module: str, tenant_id: str, deployment_id: str) -> list[str]:
        if self.backend != "s3":
            return []
        args = [
            "-reconfigure",
            f"-backend-config=bucket={self.bucket}",
            f"-backend-config=key={self.key_for(module, tenant_id, deployment_id)}",
            f"-backend-config=region={self.region}",
            f"-backend-config=dynamodb_table={self.lock_table}",
            "-backend-config=encrypt=true",
        ]
        if self.endpoint:
            args.append(f"-backend-config=endpoint={self.endpoint}")
        if self.role_arn:
            args.append(f"-backend-config=assume_role.role_arn={self.role_arn}")
        return args


class SecretManager:
    """Small provider-neutral secret manager interface."""

    def get(self, name: str) -> str:  # pragma: no cover - interface guard
        raise NotImplementedError

    def rotate(self, name: str) -> None:  # pragma: no cover - interface guard
        raise NotImplementedError

    def values(self, names: Iterable[str]) -> Dict[str, str]:
        values = {name: self.get(name) for name in names}
        if any(not value for value in values.values()):
            raise StateSecurityError("secret manager returned an empty secret")
        return values


class EnvironmentSecretManager(SecretManager):
    """Test-only secret source; never permitted for real deploys."""

    def get(self, name: str) -> str:
        value = os.getenv(name, "").strip()
        if not value:
            raise StateSecurityError(f"required test secret is missing: {name}")
        return value

    def rotate(self, name: str) -> None:
        raise StateSecurityError("environment secrets cannot be rotated")


class AwsSecretsManager(SecretManager):
    """AWS Secrets Manager adapter using the external AWS CLI.

    IAM credentials/roles are supplied by the execution environment.  Secret
    values are captured in memory and never passed as command-line arguments.
    """

    def __init__(self, *, prefix: str, region: str, command: str = "aws") -> None:
        self.prefix = prefix.rstrip("/")
        self.region = region
        self.command = command

    def _secret_id(self, name: str) -> str:
        if not _SAFE_NAME.fullmatch(name):
            raise StateSecurityError(f"invalid secret name: {name}")
        return f"{self.prefix}/{name}"

    def _run(self, args: list[str]) -> str:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise StateSecurityError(f"secret manager command failed: {exc}") from exc
        if result.returncode != 0:
            # Deliberately do not include stderr: provider CLIs may echo
            # request metadata or secret-manager details into diagnostics.
            raise StateSecurityError("secret manager command returned a failure")
        return result.stdout.strip()

    def get(self, name: str) -> str:
        raw = self._run([
            self.command,
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            self._secret_id(name),
            "--region",
            self.region,
            "--query",
            "SecretString",
            "--output",
            "text",
        ])
        if not raw:
            raise StateSecurityError(f"secret manager returned no value for {name}")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        if not isinstance(parsed, str) or not parsed:
            raise StateSecurityError(f"secret manager returned invalid value for {name}")
        return parsed

    def rotate(self, name: str) -> None:
        self._run([
            self.command,
            "secretsmanager",
            "rotate-secret",
            "--secret-id",
            self._secret_id(name),
            "--region",
            self.region,
            "--output",
            "json",
        ])


def secret_manager_from_env(*, allow_environment: bool = False) -> SecretManager:
    backend = os.getenv("NOCTISAPI_SECRET_BACKEND", "aws-secrets-manager").strip().lower()
    if backend == "env":
        if not allow_environment:
            raise StateSecurityError(
                "environment secrets are test-only; configure NOCTISAPI_SECRET_BACKEND=aws-secrets-manager"
            )
        return EnvironmentSecretManager()
    if backend != "aws-secrets-manager":
        raise StateSecurityError("NOCTISAPI_SECRET_BACKEND must be 'aws-secrets-manager' or 'env'")
    return AwsSecretsManager(
        prefix=_required("NOCTISAPI_SECRET_PREFIX"),
        region=_required("NOCTISAPI_SECRET_REGION"),
        command=os.getenv("NOCTISAPI_SECRET_COMMAND", "aws").strip() or "aws",
    )
