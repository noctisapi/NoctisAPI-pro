"""Runs the real render-dynamic-config.sh and checks its output -- no Docker required.

NOC-014: regression guard for the proxy-hardening properties added to the
Traefik File Provider config (TLS floor, request body cap). Executes the
actual script rather than grepping its source, so a rendering mistake (e.g.
a bad heredoc substitution) would fail this test too.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

import yaml

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_REPO_ROOT, "compose", "traefik", "render-dynamic-config.sh")


@unittest.skipUnless(shutil.which("sh"), "no POSIX sh available to run the real script")
class TestRenderedDynamicConfig(unittest.TestCase):
    def _render(self, **env_overrides: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            dyn_dir = os.path.join(tmp, "dynamic")
            os.makedirs(dyn_dir)
            script_copy = os.path.join(tmp, "render.sh")
            with open(_SCRIPT, "r", encoding="utf-8") as f:
                src = f.read()
            out_path = os.path.join(dyn_dir, "dynamic.yml").replace("\\", "/")
            src = src.replace(
                'OUT="/etc/traefik/dynamic/dynamic.yml"',
                f'OUT="{out_path}"',
            )
            with open(script_copy, "w", encoding="utf-8") as f:
                f.write(src)
            env = dict(os.environ)
            env.update(
                {
                    "HP_PUBLIC_HOST": "example.test",
                    "HP_PUBLIC_RATELIMIT_AVG": "120",
                    "HP_PUBLIC_RATELIMIT_BURST": "240",
                }
            )
            env.update(env_overrides)
            subprocess.run(["sh", script_copy], env=env, check=True, capture_output=True)
            with open(out_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)

    def test_minimum_tls_version_is_set(self):
        rendered = self._render()
        self.assertEqual(
            rendered["tls"]["options"]["default"]["minVersion"], "VersionTLS12"
        )

    def test_hp_api_has_body_size_limit_middleware(self):
        rendered = self._render()
        router = rendered["http"]["routers"]["hp-api"]
        self.assertIn("hp-body-limit", router["middlewares"])
        self.assertEqual(
            rendered["http"]["middlewares"]["hp-body-limit"]["buffering"][
                "maxRequestBodyBytes"
            ],
            26214400,
        )

    def test_body_size_limit_is_overridable(self):
        rendered = self._render(HP_PUBLIC_MAX_BODY_BYTES="1048576")
        self.assertEqual(
            rendered["http"]["middlewares"]["hp-body-limit"]["buffering"][
                "maxRequestBodyBytes"
            ],
            1048576,
        )

    def test_hp_health_and_hp_internal_do_not_carry_the_body_limit(self):
        """hp-health has no body; hp-internal is admin's own monitor traffic."""
        rendered = self._render()
        routers = rendered["http"]["routers"]
        self.assertNotIn("hp-body-limit", routers["hp-health"]["middlewares"])
        self.assertNotIn("hp-body-limit", routers["hp-internal"]["middlewares"])


if __name__ == "__main__":
    unittest.main()
