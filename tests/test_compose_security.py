"""Static checks on the compose files themselves — no Docker required.

Guards invariants that are easy to silently reintroduce in a later edit
(e.g. copy-pasting a volumes: block) but must never ship to a managed
deployment.
"""
from __future__ import annotations

import os
import unittest

import yaml

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMPOSE_DIR = os.path.join(_REPO_ROOT, "compose")


def _load_compose(filename: str) -> dict:
    path = os.path.join(_COMPOSE_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _service_volume_sources(service: dict) -> list[str]:
    """Return the host/source side of every volume entry, both list and dict form."""
    sources = []
    for entry in service.get("volumes", []) or []:
        if isinstance(entry, str):
            sources.append(entry.split(":", 1)[0])
        elif isinstance(entry, dict):
            sources.append(str(entry.get("source", "")))
    return sources


class TestDockerSocketNotMounted(unittest.TestCase):
    """NOC-008: Traefik (and nothing else) must never mount the Docker socket.

    Regression guard for NOC-007/NOC-008: Traefik now discovers routes via
    providers.file, not providers.docker, so it has no legitimate reason to
    ever touch /var/run/docker.sock again. If this test fails, something
    reintroduced Docker-socket access to the managed compose stack.
    """

    def test_no_service_mounts_docker_socket(self):
        compose = _load_compose("docker-compose.prod.yml")
        offenders = []
        for name, service in compose["services"].items():
            for source in _service_volume_sources(service):
                if "docker.sock" in source:
                    offenders.append(name)
        self.assertEqual(
            offenders,
            [],
            f"service(s) mount the Docker socket, which must stay removed: {offenders}",
        )

    def test_traefik_does_not_use_docker_provider(self):
        compose = _load_compose("docker-compose.prod.yml")
        traefik_command = compose["services"]["traefik"].get("command", [])
        docker_provider_flags = [
            arg for arg in traefik_command if "providers.docker" in str(arg)
        ]
        self.assertEqual(
            docker_provider_flags,
            [],
            f"traefik command still references providers.docker: {docker_provider_flags}",
        )
        file_provider_flags = [
            arg for arg in traefik_command if "providers.file" in str(arg)
        ]
        self.assertTrue(
            file_provider_flags,
            "traefik command should configure providers.file (File Provider routing)",
        )

    def test_dev_compose_never_mounted_docker_socket_either(self):
        compose = _load_compose("docker-compose.dev.yml")
        offenders = []
        for name, service in compose["services"].items():
            for source in _service_volume_sources(service):
                if "docker.sock" in source:
                    offenders.append(name)
        self.assertEqual(offenders, [])


class TestAdminReachableOnlyThroughCloudflareTunnel(unittest.TestCase):
    """NOC-016: the admin console must never publish a port -- the
    cloudflared sidecar is the only route to it, on net-internal only.
    """

    def test_admin_publishes_no_ports(self):
        compose = _load_compose("docker-compose.prod.yml")
        admin = compose["services"]["admin"]
        self.assertNotIn(
            "ports",
            admin,
            "admin must not publish any port -- it should only be reachable "
            "through the cloudflared sidecar over net-internal",
        )

    def test_cloudflared_service_exists_and_is_hardened(self):
        compose = _load_compose("docker-compose.prod.yml")
        services = compose["services"]
        self.assertIn("cloudflared", services)
        cloudflared = services["cloudflared"]
        self.assertEqual(cloudflared.get("cap_drop"), ["ALL"])
        self.assertTrue(cloudflared.get("read_only"))
        self.assertIn("no-new-privileges:true", cloudflared.get("security_opt", []))
        self.assertNotIn(
            "ports",
            cloudflared,
            "cloudflared must not publish any port either -- it only makes "
            "outbound connections to Cloudflare's edge",
        )

    def test_cloudflared_is_scoped_to_net_internal_only(self):
        compose = _load_compose("docker-compose.prod.yml")
        cloudflared = compose["services"]["cloudflared"]
        self.assertEqual(cloudflared.get("networks"), ["net-internal"])

    def test_cloudflared_token_is_not_hardcoded(self):
        compose = _load_compose("docker-compose.prod.yml")
        cloudflared = compose["services"]["cloudflared"]
        env = cloudflared.get("environment", [])
        token_entries = [e for e in env if str(e).startswith("TUNNEL_TOKEN=")]
        self.assertEqual(len(token_entries), 1)
        self.assertEqual(token_entries[0], "TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}")


class TestManagedOverrideStatic(unittest.TestCase):
    """NOC-023: static checks on docker-compose.managed.yml alone, read as
    its own YAML file (not merged with docker-compose.prod.yml -- the real
    merge is verified separately in tests/test_managed_compose.py, which
    needs Docker). This file is an override layer: it should only ever add
    the pinned-version/secrets delta, never introduce a port or touch the
    Docker socket itself."""

    def test_declares_hp_seed_as_a_secret(self):
        compose = _load_compose("docker-compose.managed.yml")
        self.assertIn("hp_seed", compose.get("secrets", {}))

    def test_migrate_app_admin_all_use_the_hp_seed_secret(self):
        compose = _load_compose("docker-compose.managed.yml")
        for name in ("migrate", "app", "admin"):
            service = compose["services"][name]
            self.assertIn("hp_seed", service.get("secrets", []), f"{name} is missing the hp_seed secret")

    def test_migrate_app_admin_pin_to_managed_app_version(self):
        compose = _load_compose("docker-compose.managed.yml")
        for name in ("migrate", "app", "admin"):
            image = compose["services"][name]["image"]
            self.assertIn("${MANAGED_APP_VERSION}", image, f"{name}: {image}")
            self.assertNotIn(":latest", image)

    def test_override_introduces_no_ports_on_any_service(self):
        compose = _load_compose("docker-compose.managed.yml")
        offenders = [name for name, service in compose["services"].items() if "ports" in service]
        self.assertEqual(offenders, [], f"managed override must not publish any port: {offenders}")

    def test_override_mounts_no_docker_socket(self):
        compose = _load_compose("docker-compose.managed.yml")
        offenders = []
        for name, service in compose["services"].items():
            for source in _service_volume_sources(service):
                if "docker.sock" in source:
                    offenders.append(name)
        self.assertEqual(offenders, [])


class TestEveryLongRunningServiceHasAHealthcheck(unittest.TestCase):
    """NOC-028: admin had no healthcheck at all before this, and traefik's
    was added alongside it -- regression guard so a future edit can't
    silently drop one again. migrate/traefik-config are one-shot (they're
    supposed to exit, not stay healthy) and are deliberately excluded."""

    def test_app_admin_cloudflared_traefik_all_define_a_healthcheck(self):
        compose = _load_compose("docker-compose.prod.yml")
        missing = [
            name
            for name in ("app", "admin", "cloudflared", "traefik")
            if "healthcheck" not in compose["services"][name]
        ]
        self.assertEqual(missing, [], f"service(s) missing a healthcheck: {missing}")

    def test_app_and_admin_healthchecks_also_check_the_http_server(self):
        compose = _load_compose("docker-compose.prod.yml")
        for name, port in (("app", "8000"), ("admin", "9001")):
            test_cmd = compose["services"][name]["healthcheck"]["test"]
            self.assertIn("--http-port", test_cmd, f"{name}'s healthcheck doesn't check its HTTP server")
            self.assertIn(port, test_cmd, f"{name}'s healthcheck doesn't check port {port}")

    def test_traefik_ping_entrypoint_is_never_published(self):
        compose = _load_compose("docker-compose.prod.yml")
        traefik = compose["services"]["traefik"]
        published = [str(p) for p in traefik.get("ports", [])]
        self.assertFalse(
            any("8082" in p for p in published),
            "the ping entrypoint must stay internal to the container -- the "
            "healthcheck reaches it over the container's own loopback, no "
            "port mapping needed or wanted",
        )


if __name__ == "__main__":
    unittest.main()
