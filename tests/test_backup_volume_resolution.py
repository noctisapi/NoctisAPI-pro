"""NOC-026: backup_sqlite.sh / restore_backup.sh resolve the actual Docker
volume/image names via `docker compose config --format json` instead of a
hardcoded guess -- a stale guess doesn't error, it silently backs up a
freshly auto-created EMPTY volume (the exact bug this guards against: the
pre-existing script hardcoded `honey_app_hp_prod_data`, a volume name from
before this project's compose files were reorganized).

Docker-gated like tests/test_proxy_adversarial.py and tests/test_managed_compose.py.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMPOSE_FILE = os.path.join(_REPO_ROOT, "compose", "docker-compose.prod.yml")


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


def _render_config(project_name: str) -> dict:
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
            "COMPOSE_PROJECT_NAME": project_name,
        }
    )
    result = subprocess.run(
        ["docker", "compose", "-f", _COMPOSE_FILE, "--env-file", env_prod_path, "config", "--format", "json"],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True, timeout=30,
    )
    result.check_returncode()
    return json.loads(result.stdout)


@unittest.skipUnless(_docker_available(), "Docker is not available in this environment")
class TestVolumeNameResolution(unittest.TestCase):
    def test_hp_prod_data_volume_name_is_resolved_with_the_project_prefix(self):
        config = _render_config("my_test_project")
        self.assertEqual(config["volumes"]["hp_prod_data"]["name"], "my_test_project_hp_prod_data")

    def test_hp_prod_myapp_volume_name_is_resolved_with_the_project_prefix(self):
        config = _render_config("my_test_project")
        self.assertEqual(config["volumes"]["hp_prod_myapp"]["name"], "my_test_project_hp_prod_myapp")

    def test_resolved_name_changes_with_a_different_project_name(self):
        """The whole point: the volume name is NOT a fixed string -- a
        script that hardcodes one guess will be wrong under a different
        project name, silently, with no error."""
        config_a = _render_config("project_a")
        config_b = _render_config("project_b")
        self.assertNotEqual(
            config_a["volumes"]["hp_prod_data"]["name"],
            config_b["volumes"]["hp_prod_data"]["name"],
        )

    def test_app_image_is_present_for_the_encryption_step(self):
        config = _render_config("my_test_project")
        self.assertIn("image", config["services"]["app"])
        self.assertTrue(config["services"]["app"]["image"])


if __name__ == "__main__":
    unittest.main()
