"""NOC-023: the Managed compose variant, merged for real via `docker compose
config` (not just parsed as two separate YAML files) -- the same
Docker-availability-gated pattern as tests/test_proxy_adversarial.py.

Static per-file checks (no Docker needed) live in tests/test_compose_security.py.
This file verifies what only the real merge can prove: that layering
docker-compose.managed.yml on top of docker-compose.prod.yml produces an
effective config that still has no admin port, no Docker socket, pinned
images, and the HP_SEED secret wired to app/admin/migrate -- i.e. NOC-023's
"compose config valida sin errores" and "no expone admin ni Docker Socket"
acceptance criteria against the configuration an operator would actually run.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMPOSE_DIR = os.path.join(_REPO_ROOT, "compose")


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


def _render_merged_config() -> dict:
    # docker-compose.prod.yml's services declare env_file: ../.env.prod, so
    # docker compose config needs that path to exist to resolve it -- same
    # requirement the "Validate prod/managed compose" CI steps meet with
    # `touch .env.prod`. Non-destructive: only creates it if absent, never
    # truncates a real one a developer has locally.
    env_prod_path = os.path.join(_REPO_ROOT, ".env.prod")
    if not os.path.exists(env_prod_path):
        open(env_prod_path, "a", encoding="utf-8").close()

    env = dict(os.environ)
    env.update(
        {
            "HP_PUBLIC_HOST": "test.invalid",
            "HP_PANEL_TOKEN": "test-panel-token",
            "ACME_EMAIL": "test@example.invalid",
            "APP_VERSION": "test-version",
            "CLOUDFLARE_TUNNEL_TOKEN": "test-tunnel-token",
            "MANAGED_APP_VERSION": "1.2.3-test",
        }
    )
    result = subprocess.run(
        [
            "docker", "compose",
            "-f", os.path.join(_COMPOSE_DIR, "docker-compose.prod.yml"),
            "-f", os.path.join(_COMPOSE_DIR, "docker-compose.managed.yml"),
            "--env-file", env_prod_path,
            "config", "--format", "json",
        ],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    result.check_returncode()
    return json.loads(result.stdout)


@unittest.skipUnless(_docker_available(), "Docker is not available in this environment")
class TestManagedComposeMerge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = _render_merged_config()

    def test_config_validates_without_errors(self):
        # _render_merged_config() already raised via check_returncode() if
        # `docker compose config` failed -- reaching here is the assertion.
        self.assertIn("services", self.config)

    def test_image_is_pinned_to_managed_app_version_not_latest(self):
        for name in ("migrate", "app", "admin"):
            image = self.config["services"][name]["image"]
            self.assertTrue(image.endswith(":1.2.3-test"), f"{name}: {image}")
            self.assertNotIn(":latest", image)

    def test_hp_seed_is_delivered_as_a_secret_not_a_plain_value(self):
        for name in ("migrate", "app", "admin"):
            service = self.config["services"][name]
            secret_names = {s["source"] for s in service.get("secrets", [])}
            self.assertIn("hp_seed", secret_names)
            env = service.get("environment", {})
            self.assertEqual(env.get("HP_SEED_FILE"), "/run/secrets/hp_seed")

    def test_admin_still_publishes_no_ports(self):
        self.assertNotIn("ports", self.config["services"]["admin"])

    def test_no_service_mounts_the_docker_socket(self):
        for name, service in self.config["services"].items():
            for volume in service.get("volumes", []) or []:
                source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":")[0]
                self.assertNotIn("docker.sock", source, f"{name} mounts the Docker socket")


if __name__ == "__main__":
    unittest.main()
