#!/usr/bin/env python3
"""
Private operator CLI for Managed PRO deployments (NOC-035).

The CLI deliberately orchestrates the already-reviewed building blocks:

* Terraform Cloudflare creates the tunnel and Access perimeter.
* Terraform Hetzner creates the VPS and passes the tunnel token to cloud-init.
* cloud-init runs the application bootstrap and writes ``.bootstrap-status``.
* the existing ``scripts/verify.py`` is the final deployment gate.

Secret values are accepted only through environment variables and are never
included in subprocess arguments or log output. Terraform state remains local
for now; NOC-038 owns the remote encrypted backend and secrets-manager work.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_MANIFEST = _REPO_ROOT / "compose" / "secrets" / "deployment-manifest.json"
_DEFAULT_STATE_ROOT = _REPO_ROOT / "compose" / "secrets" / "deployer-state"
_CLOUDFLARE_DIR = _REPO_ROOT / "terraform" / "cloudflare"
_HETZNER_DIR = _REPO_ROOT / "terraform" / "hetzner"

sys.path.insert(0, str(_REPO_ROOT))
from scripts import deployment_manifest as manifest_lib  # noqa: E402
from scripts import init_deployment  # noqa: E402


class DeployerError(RuntimeError):
    """An operator-actionable deployment failure."""


@dataclass
class DeploymentConfig:
    customer_id: str
    region: str
    sizing: str
    public_host: str
    admin_host: str
    acme_email: str
    app_version: str
    ssh_public_key: str
    ssh_private_key: Optional[Path]
    ssh_user: str
    ssh_allowed_cidrs: List[str]
    cloudflare_account_id: str
    access_allowed_emails: List[str]
    admin_zone_id: str = ""
    public_zone_id: str = ""
    enable_access_application: bool = True
    ghcr_token: str = ""
    terraform_timeout: int = 900
    ssh_attempts: int = 30
    ssh_retry_delay: float = 5.0
    accept_new_host_key: bool = False


@dataclass
class DeploymentPaths:
    manifest: Path
    state_dir: Path
    cloudflare_state: Path
    hetzner_state: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        try:
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _secret_env(name: str, *, required: bool = True) -> str:
    value = os.getenv(name, "").strip()
    if required and not value:
        raise DeployerError(f"required secret environment variable is missing: {name}")
    return value


def _redact(text: str, secrets: Iterable[str]) -> str:
    redacted = text
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


class CommandRunner:
    """Runs operator commands while keeping output out of normal logs."""

    def __init__(self, *, secrets: Iterable[str] = ()) -> None:
        self.secrets = tuple(secrets)

    def run(
        self,
        args: Sequence[str],
        *,
        label: str,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: int = 900,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        print(f"[deployer] {label}")
        try:
            result = subprocess.run(
                list(args),
                cwd=str(cwd) if cwd else None,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeployerError(f"{label} could not run: {_redact(str(exc), self.secrets)}") from exc
        if check and result.returncode != 0:
            detail = _redact((result.stderr or result.stdout or "").strip(), self.secrets)
            if len(detail) > 1200:
                detail = detail[-1200:]
            raise DeployerError(f"{label} failed with exit code {result.returncode}: {detail}")
        return result


def _load_manifest(path: Path) -> dict:
    if not path.exists():
        return {"deployment_id": uuid.uuid4().hex, "created_at": _utc_now()}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployerError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DeployerError(f"manifest {path} must contain a JSON object")
    return value


def _prepare_manifest(path: Path, config: DeploymentConfig, *, persist: bool) -> dict:
    manifest = _load_manifest(path)
    if not manifest.get("deployment_id"):
        manifest["deployment_id"] = uuid.uuid4().hex
    manifest.setdefault("created_at", _utc_now())
    manifest.setdefault("schema_version", manifest_lib.SCHEMA_VERSION)

    current_status = manifest.get("status")
    if current_status == manifest_lib.DeploymentStatus.DECOMMISSIONED.value:
        raise DeployerError("deployment is decommissioned; use a new deployment_id")
    if current_status == manifest_lib.DeploymentStatus.FAILED.value:
        manifest_lib.set_status(manifest, manifest_lib.DeploymentStatus.PROVISIONING, reason="retry deploy")
    elif not current_status:
        manifest["status"] = manifest_lib.DeploymentStatus.PROVISIONING.value

    manifest["updated_at"] = _utc_now()
    for key, value in {
        "customer_id": config.customer_id,
        "region": config.region,
        "sizing": config.sizing,
        "plan": "managed",
        "hp_public_host": config.public_host,
        "hp_admin_host": config.admin_host,
    }.items():
        if value:
            manifest[key] = value

    errors = manifest_lib.validate_manifest(manifest)
    if errors:
        raise DeployerError("invalid deployment manifest: " + "; ".join(errors))
    if persist:
        _write_json(path, manifest)
    return manifest


def _paths_for(manifest_path: Path, deployment_id: str, state_dir: Optional[Path]) -> DeploymentPaths:
    if state_dir is None:
        state_dir = manifest_path.parent / "deployer-state" / deployment_id
    state_dir = state_dir.resolve()
    return DeploymentPaths(
        manifest=manifest_path.resolve(),
        state_dir=state_dir,
        cloudflare_state=state_dir / "cloudflare.tfstate",
        hetzner_state=state_dir / "hetzner.tfstate",
    )


def _terraform_env(extra: Optional[Dict[str, str]] = None, *, data_dir: Optional[Path] = None) -> Dict[str, str]:
    environment = os.environ.copy()
    if extra:
        environment.update(extra)
    if data_dir:
        environment["TF_DATA_DIR"] = str(data_dir)
    return environment


def _tf_var_args(values: Dict[str, object]) -> List[str]:
    result: List[str] = []
    for key, value in values.items():
        if value in (None, "", []):
            continue
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, list):
            rendered = json.dumps(value, separators=(",", ":"))
        else:
            rendered = str(value)
        result.extend(["-var", f"{key}={rendered}"])
    return result


def _terraform_init(runner: CommandRunner, module: Path, paths: DeploymentPaths, *, dry_run: bool) -> None:
    data_dir = paths.state_dir / f".terraform-{module.name}"
    args = [f"-chdir={module}", "init", "-input=false"]
    if dry_run:
        args.append("-backend=false")
    runner.run(args, label=f"terraform init ({module.name})", timeout=600, env=_terraform_env(data_dir=data_dir))
    runner.run(
        [f"-chdir={module}", "validate"],
        label=f"terraform validate ({module.name})",
        timeout=180,
        env=_terraform_env(data_dir=data_dir),
    )


def _terraform_plan_apply(
    runner: CommandRunner,
    module: Path,
    state_path: Path,
    variables: Dict[str, object],
    secret_env: Dict[str, str],
    *,
    apply: bool,
    timeout: int,
    label: str,
) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    data_dir = state_path.parent / f".terraform-{module.name}"
    environment = _terraform_env(secret_env, data_dir=data_dir)
    plan_path = state_path.with_suffix(".tfplan")
    plan_args = [
        f"-chdir={module}", "plan", "-input=false", "-lock-timeout=30s",
        f"-state={state_path}", f"-out={plan_path}", *_tf_var_args(variables),
    ]
    runner.run(plan_args, label=f"{label}: plan", timeout=timeout, env=environment)
    if apply:
        runner.run(
            [f"-chdir={module}", "apply", "-input=false", "-auto-approve", f"-state={state_path}", str(plan_path)],
            label=f"{label}: apply",
            timeout=timeout,
            env=environment,
        )


def _terraform_output(runner: CommandRunner, module: Path, state_path: Path, name: str, *, secrets: Iterable[str]) -> str:
    result = runner.run(
        [f"-chdir={module}", "output", "-raw", f"-state={state_path}", name],
        label=f"read Terraform output {name}",
        timeout=120,
    )
    value = result.stdout.strip()
    if not value:
        raise DeployerError(f"Terraform output {name} was empty")
    return value


def _ssh_args(config: DeploymentConfig, host: str, remote_command: str) -> List[str]:
    if not config.ssh_private_key:
        raise DeployerError("an SSH private key is required for remote status/verify")
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if config.accept_new_host_key:
        args.extend(["-o", "StrictHostKeyChecking=accept-new"])
    args.extend(["-i", str(config.ssh_private_key), f"{config.ssh_user}@{host}", remote_command])
    return args


def _remote_verify_command(config: DeploymentConfig, host: str, expected_ip: str) -> str:
    values = [
        "sudo -n python3 /opt/hp-app/scripts/verify.py",
        "--managed",
        f"--host {shlex.quote(config.public_host)}",
        f"--admin-host {shlex.quote(config.admin_host)}",
        f"--expected-ip {shlex.quote(expected_ip)}",
        "--env-file /opt/hp-app/.env.prod",
        "--backup-dir /opt/hp-app/backups",
        "--secrets-dir /opt/hp-app/compose/secrets",
        "--cron-file /etc/cron.d/noctisapi-backup",
    ]
    return " ".join(values)


def _remote_status_command() -> str:
    return (
        "sudo -n bash -lc "
        + shlex.quote(
            "printf 'bootstrap-status='; cat /opt/hp-app/.bootstrap-status 2>/dev/null || true; "
            "printf '\\n'; "
            "docker compose --env-file /opt/hp-app/.env.prod "
            "-f /opt/hp-app/compose/docker-compose.prod.yml "
            "-f /opt/hp-app/compose/docker-compose.managed.yml "
            "ps --format json"
        )
    )


def _wait_for_ssh(runner: CommandRunner, config: DeploymentConfig, host: str) -> subprocess.CompletedProcess[str]:
    last: Optional[DeployerError] = None
    for attempt in range(1, config.ssh_attempts + 1):
        try:
            return runner.run(
                _ssh_args(config, host, "test \"$(sudo -n cat /opt/hp-app/.bootstrap-status 2>/dev/null)\" = ok"),
                label=f"wait for bootstrap (attempt {attempt}/{config.ssh_attempts})",
                timeout=30,
            )
        except DeployerError as exc:
            last = exc
            if attempt < config.ssh_attempts and config.ssh_retry_delay:
                time.sleep(config.ssh_retry_delay)
    raise last or DeployerError("bootstrap did not become ready")


def _set_final_status(paths: DeploymentPaths, manifest: dict, status: manifest_lib.DeploymentStatus, reason: str = "") -> None:
    current = manifest.get("status")
    if current != status.value:
        try:
            manifest_lib.set_status(manifest, status, reason=reason)
        except manifest_lib.InvalidTransition:
            # A failed verification after a previously active re-run is a
            # degradation, not an invalid active -> failed transition.
            if status == manifest_lib.DeploymentStatus.FAILED and current == manifest_lib.DeploymentStatus.ACTIVE:
                manifest_lib.set_status(manifest, manifest_lib.DeploymentStatus.DEGRADED, reason=reason)
            else:
                raise
    _write_json(paths.manifest, manifest)


def _validate_config(config: DeploymentConfig) -> None:
    fields = {
        "customer_id": config.customer_id,
        "region": config.region,
        "sizing": config.sizing,
        "public_host": config.public_host,
        "admin_host": config.admin_host,
        "acme_email": config.acme_email,
        "app_version": config.app_version,
        "cloudflare_account_id": config.cloudflare_account_id,
    }
    missing = [name for name, value in fields.items() if not value]
    if missing:
        raise DeployerError("missing deploy argument(s): " + ", ".join(missing))
    if config.app_version == "latest":
        raise DeployerError('app_version must be an immutable tag, not "latest"')
    if not config.ssh_public_key.strip():
        raise DeployerError("SSH public key must not be empty")
    if not config.ssh_allowed_cidrs:
        raise DeployerError("at least one SSH allowed CIDR is required")
    if config.enable_access_application and not config.access_allowed_emails:
        raise DeployerError("at least one access email is required when Access is enabled")
    if config.ssh_private_key and not config.ssh_private_key.exists():
        raise DeployerError(f"SSH private key does not exist: {config.ssh_private_key}")


def deploy(config: DeploymentConfig, *, manifest_path: Path, state_dir: Optional[Path], dry_run: bool = False, skip_verify: bool = False) -> int:
    _validate_config(config)
    provisional = _load_manifest(manifest_path)
    deployment_id = provisional.get("deployment_id") or uuid.uuid4().hex
    paths = _paths_for(manifest_path, deployment_id, state_dir)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    manifest = _prepare_manifest(paths.manifest, config, persist=not dry_run)

    if dry_run:
        runner = CommandRunner()
        _terraform_init(runner, _CLOUDFLARE_DIR, paths, dry_run=True)
        _terraform_init(runner, _HETZNER_DIR, paths, dry_run=True)
        print(f"[deployer] dry-run valid for deployment_id={manifest['deployment_id']}")
        return 0

    secret_values = {
        "HCLOUD_TOKEN": _secret_env("HCLOUD_TOKEN"),
        "CLOUDFLARE_API_TOKEN": _secret_env("CLOUDFLARE_API_TOKEN"),
        "GIT_DEPLOY_TOKEN": _secret_env("GIT_DEPLOY_TOKEN"),
    }
    config.ghcr_token = os.getenv("GHCR_TOKEN", "").strip()
    if config.ghcr_token:
        secret_values["GHCR_TOKEN"] = config.ghcr_token
    runner = CommandRunner(secrets=secret_values.values())
    try:
        _terraform_init(runner, _CLOUDFLARE_DIR, paths, dry_run=False)
        _terraform_init(runner, _HETZNER_DIR, paths, dry_run=False)

        cloudflare_vars = {
            "account_id": config.cloudflare_account_id,
            "deployment_id": manifest["deployment_id"],
            "admin_hostname": config.admin_host,
            "admin_zone_id": config.admin_zone_id,
            "public_hostname": config.public_host,
            "public_zone_id": config.public_zone_id,
            "access_allowed_emails": config.access_allowed_emails,
            "enable_access_application": config.enable_access_application,
        }
        cloudflare_env = {"CLOUDFLARE_API_TOKEN": secret_values["CLOUDFLARE_API_TOKEN"]}
        _terraform_plan_apply(
            runner, _CLOUDFLARE_DIR, paths.cloudflare_state, cloudflare_vars, cloudflare_env,
            apply=True, timeout=config.terraform_timeout, label="Cloudflare perimeter",
        )
        tunnel_token = _terraform_output(runner, _CLOUDFLARE_DIR, paths.cloudflare_state, "tunnel_token", secrets=runner.secrets)
        runner.secrets = (*runner.secrets, tunnel_token)

        hetzner_vars = {
            "deployment_id": manifest["deployment_id"],
            "customer_id": config.customer_id,
            "region": config.region,
            "sizing": config.sizing,
            "ssh_public_key": config.ssh_public_key,
            "ssh_allowed_cidrs": config.ssh_allowed_cidrs,
            "app_version": config.app_version,
            "hp_public_host": config.public_host,
            "hp_admin_host": config.admin_host,
            "acme_email": config.acme_email,
            "cloudflare_tunnel_token": tunnel_token,
            "ghcr_token": config.ghcr_token,
        }
        hetzner_env = {
            "HCLOUD_TOKEN": secret_values["HCLOUD_TOKEN"],
            "TF_VAR_git_deploy_token": secret_values["GIT_DEPLOY_TOKEN"],
            "TF_VAR_cloudflare_tunnel_token": tunnel_token,
            "TF_VAR_ghcr_token": config.ghcr_token,
        }
        # Remove the sensitive variables from argv. _tf_var_args skips these
        # values below; they are present only in the subprocess environment.
        hetzner_vars["cloudflare_tunnel_token"] = ""
        hetzner_vars["ghcr_token"] = ""
        _terraform_plan_apply(
            runner, _HETZNER_DIR, paths.hetzner_state, hetzner_vars, hetzner_env,
            apply=True, timeout=config.terraform_timeout, label="Hetzner VPS and bootstrap",
        )
        server_ipv4 = _terraform_output(runner, _HETZNER_DIR, paths.hetzner_state, "server_ipv4", secrets=runner.secrets)

        if config.public_zone_id:
            cloudflare_vars["vps_ipv4"] = server_ipv4
            _terraform_plan_apply(
                runner, _CLOUDFLARE_DIR, paths.cloudflare_state, cloudflare_vars, cloudflare_env,
                apply=True, timeout=config.terraform_timeout, label="Cloudflare public DNS",
            )

        if not skip_verify:
            _wait_for_ssh(runner, config, server_ipv4)
            runner.run(
                _ssh_args(config, server_ipv4, _remote_verify_command(config, server_ipv4, server_ipv4)),
                label="remote deployment verification",
                timeout=300,
            )
        _set_final_status(paths, manifest, manifest_lib.DeploymentStatus.ACTIVE, "deploy verified")
        print(f"[deployer] deployment active: id={manifest['deployment_id']} server_ipv4={server_ipv4}")
        return 0
    except Exception as exc:
        try:
            _set_final_status(paths, manifest, manifest_lib.DeploymentStatus.FAILED, _redact(str(exc), runner.secrets))
        except Exception as status_exc:
            print(f"[deployer] could not record failed status: {_redact(str(status_exc), runner.secrets)}", file=sys.stderr)
        safe_message = _redact(str(exc), runner.secrets)
        raise DeployerError(safe_message) from exc


def _read_deployment(paths: DeploymentPaths) -> dict:
    manifest = _load_manifest(paths.manifest)
    errors = manifest_lib.validate_manifest(manifest)
    if errors:
        raise DeployerError("invalid deployment manifest: " + "; ".join(errors))
    if not paths.hetzner_state.exists():
        raise DeployerError(f"Hetzner state does not exist: {paths.hetzner_state}")
    return manifest


def status(
    *,
    manifest_path: Path,
    state_dir: Optional[Path],
    ssh_private_key: Optional[Path],
    ssh_user: str,
    accept_new_host_key: bool,
    remote: bool,
) -> int:
    manifest_probe = _load_manifest(manifest_path)
    deployment_id = manifest_probe.get("deployment_id")
    if not deployment_id:
        raise DeployerError("manifest has no deployment_id")
    paths = _paths_for(manifest_path, deployment_id, state_dir)
    manifest = _read_deployment(paths)
    runner = CommandRunner()
    config = DeploymentConfig(
        customer_id=manifest.get("customer_id", ""), region=manifest.get("region", ""),
        sizing=manifest.get("sizing", ""), public_host=manifest.get("hp_public_host", ""),
        admin_host=manifest.get("hp_admin_host", ""), acme_email="", app_version="",
        ssh_public_key="", ssh_private_key=ssh_private_key, ssh_user=ssh_user,
        ssh_allowed_cidrs=[], cloudflare_account_id="", access_allowed_emails=[],
        accept_new_host_key=accept_new_host_key,
    )
    ip = _terraform_output(runner, _HETZNER_DIR, paths.hetzner_state, "server_ipv4", secrets=())
    print(json.dumps({"deployment_id": deployment_id, "status": manifest.get("status"), "server_ipv4": ip}, sort_keys=True))
    if remote:
        runner.run(_ssh_args(config, ip, _remote_status_command()), label="remote deployment status", timeout=60)
    return 0


def verify(
    *,
    manifest_path: Path,
    state_dir: Optional[Path],
    ssh_private_key: Path,
    ssh_user: str,
    accept_new_host_key: bool,
) -> int:
    manifest_probe = _load_manifest(manifest_path)
    deployment_id = manifest_probe.get("deployment_id")
    if not deployment_id:
        raise DeployerError("manifest has no deployment_id")
    paths = _paths_for(manifest_path, deployment_id, state_dir)
    manifest = _read_deployment(paths)
    config = DeploymentConfig(
        customer_id=manifest.get("customer_id", ""), region=manifest.get("region", ""),
        sizing=manifest.get("sizing", ""), public_host=manifest.get("hp_public_host", ""),
        admin_host=manifest.get("hp_admin_host", ""), acme_email="", app_version="",
        ssh_public_key="", ssh_private_key=ssh_private_key, ssh_user=ssh_user,
        ssh_allowed_cidrs=[], cloudflare_account_id="", access_allowed_emails=[],
        accept_new_host_key=accept_new_host_key,
    )
    runner = CommandRunner()
    ip = _terraform_output(runner, _HETZNER_DIR, paths.hetzner_state, "server_ipv4", secrets=())
    runner.run(
        _ssh_args(config, ip, _remote_verify_command(config, ip, ip)),
        label="remote deployment verification",
        timeout=300,
    )
    return 0


def _add_remote_options(parser: argparse.ArgumentParser, *, required_key: bool) -> None:
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--ssh-private-key-file", type=Path, required=required_key)
    parser.add_argument("--ssh-user", default="noctisops")
    parser.add_argument("--accept-new-host-key", action="store_true")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    deploy_parser = sub.add_parser("deploy", help="Provision or reconcile one Managed instance")
    deploy_parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    deploy_parser.add_argument("--state-dir", type=Path)
    deploy_parser.add_argument("--customer-id", required=True)
    deploy_parser.add_argument("--region", required=True)
    deploy_parser.add_argument("--sizing", required=True)
    deploy_parser.add_argument("--public-host", required=True)
    deploy_parser.add_argument("--admin-host", required=True)
    deploy_parser.add_argument("--acme-email", required=True)
    deploy_parser.add_argument("--app-version", required=True)
    deploy_parser.add_argument("--ssh-public-key-file", type=Path, required=True)
    deploy_parser.add_argument("--ssh-private-key-file", type=Path)
    deploy_parser.add_argument("--ssh-user", default="noctisops")
    deploy_parser.add_argument("--ssh-allowed-cidr", action="append", dest="ssh_allowed_cidrs", required=True)
    deploy_parser.add_argument("--cloudflare-account-id", required=True)
    deploy_parser.add_argument("--access-email", action="append", dest="access_allowed_emails", default=[])
    deploy_parser.add_argument("--admin-zone-id", default="")
    deploy_parser.add_argument("--public-zone-id", default="")
    deploy_parser.add_argument("--disable-access-application", action="store_true")
    deploy_parser.add_argument("--terraform-timeout", type=int, default=900)
    deploy_parser.add_argument("--ssh-attempts", type=int, default=30)
    deploy_parser.add_argument("--ssh-retry-delay", type=float, default=5.0)
    deploy_parser.add_argument("--accept-new-host-key", action="store_true")
    deploy_parser.add_argument("--dry-run", action="store_true", help="Validate Terraform without contacting providers or changing state")
    deploy_parser.add_argument("--skip-verify", action="store_true", help="Do not run the remote verification gate")

    status_parser = sub.add_parser("status", help="Show manifest and VPS status")
    _add_remote_options(status_parser, required_key=False)
    status_parser.add_argument("--no-remote", action="store_true")

    verify_parser = sub.add_parser("verify", help="Run the full remote post-install verification")
    _add_remote_options(verify_parser, required_key=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "deploy":
            try:
                public_key = args.ssh_public_key_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise DeployerError(f"cannot read SSH public key: {exc}") from exc
            config = DeploymentConfig(
                customer_id=args.customer_id, region=args.region, sizing=args.sizing,
                public_host=args.public_host, admin_host=args.admin_host, acme_email=args.acme_email,
                app_version=args.app_version, ssh_public_key=public_key,
                ssh_private_key=args.ssh_private_key_file, ssh_user=args.ssh_user,
                ssh_allowed_cidrs=args.ssh_allowed_cidrs,
                cloudflare_account_id=args.cloudflare_account_id,
                access_allowed_emails=args.access_allowed_emails,
                admin_zone_id=args.admin_zone_id, public_zone_id=args.public_zone_id,
                enable_access_application=not args.disable_access_application,
                terraform_timeout=args.terraform_timeout, ssh_attempts=args.ssh_attempts,
                ssh_retry_delay=args.ssh_retry_delay, accept_new_host_key=args.accept_new_host_key,
            )
            return deploy(config, manifest_path=args.manifest, state_dir=args.state_dir, dry_run=args.dry_run, skip_verify=args.skip_verify)
        if args.command == "status":
            return status(
                manifest_path=args.manifest, state_dir=args.state_dir,
                ssh_private_key=args.ssh_private_key_file, ssh_user=args.ssh_user,
                accept_new_host_key=args.accept_new_host_key, remote=not args.no_remote,
            )
        if args.command == "verify":
            return verify(
                manifest_path=args.manifest, state_dir=args.state_dir,
                ssh_private_key=args.ssh_private_key_file, ssh_user=args.ssh_user,
                accept_new_host_key=args.accept_new_host_key,
            )
        raise DeployerError(f"unknown command: {args.command}")
    except DeployerError as exc:
        print(f"[deployer] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
