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


if __name__ == "__main__":
    unittest.main()
