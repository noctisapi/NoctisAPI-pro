"""NOC-023: Docker-secret-aware env var resolution (app.docker_secrets)."""
from __future__ import annotations

import os
import unittest

from app import docker_secrets


class TestReadSecret(unittest.TestCase):
    def setUp(self):
        self._old_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)

    def test_plain_env_var_is_used_when_no_file_var_set(self):
        os.environ.pop("HP_TEST_SECRET_FILE", None)
        os.environ["HP_TEST_SECRET"] = "plain-value"
        self.assertEqual(docker_secrets.read_secret("HP_TEST_SECRET"), "plain-value")

    def test_file_takes_priority_over_plain_env_var(self):
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("from-the-file\n")
            path = f.name
        try:
            os.environ["HP_TEST_SECRET_FILE"] = path
            os.environ["HP_TEST_SECRET"] = "plain-value-should-be-ignored"
            self.assertEqual(docker_secrets.read_secret("HP_TEST_SECRET"), "from-the-file")
        finally:
            os.unlink(path)

    def test_file_content_is_stripped(self):
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("  value-with-whitespace  \n\n")
            path = f.name
        try:
            os.environ["HP_TEST_SECRET_FILE"] = path
            self.assertEqual(docker_secrets.read_secret("HP_TEST_SECRET"), "value-with-whitespace")
        finally:
            os.unlink(path)

    def test_missing_file_falls_back_to_plain_env_var(self):
        os.environ["HP_TEST_SECRET_FILE"] = "/this/path/does/not/exist.txt"
        os.environ["HP_TEST_SECRET"] = "fallback-value"
        self.assertEqual(docker_secrets.read_secret("HP_TEST_SECRET"), "fallback-value")

    def test_default_is_used_when_nothing_is_set(self):
        os.environ.pop("HP_TEST_SECRET_FILE", None)
        os.environ.pop("HP_TEST_SECRET", None)
        self.assertEqual(docker_secrets.read_secret("HP_TEST_SECRET", "the-default"), "the-default")

    def test_empty_file_var_is_treated_as_unset(self):
        os.environ["HP_TEST_SECRET_FILE"] = "   "
        os.environ["HP_TEST_SECRET"] = "plain-value"
        self.assertEqual(docker_secrets.read_secret("HP_TEST_SECRET"), "plain-value")


if __name__ == "__main__":
    unittest.main()
