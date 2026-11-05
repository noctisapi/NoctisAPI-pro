"""NOC-024 acceptance criterion: "No se altera base URL o URLs públicas
incorrectamente". This Issue adds a verification script and documentation
only -- it does not touch app.honeypot_public's HP_PUBLIC_BASE_URL
derivation at all. This test exists to make that criterion concretely
checked rather than merely asserted by absence of a diff: setting a
customer's own HP_PUBLIC_HOST (the whole point of NOC-024) must still
produce the exact same base URL it always did.
"""
from __future__ import annotations

import importlib
import os
import unittest

import app.honeypot_public as honeypot_public


class TestPublicBaseUrlDerivation(unittest.TestCase):
    def setUp(self):
        self._old_host = os.environ.get("HP_PUBLIC_HOST")
        self._old_base = os.environ.get("HP_PUBLIC_BASE_URL")

    def tearDown(self):
        for key, old in (("HP_PUBLIC_HOST", self._old_host), ("HP_PUBLIC_BASE_URL", self._old_base)):
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        importlib.reload(honeypot_public)

    def test_custom_client_domain_derives_https_base_url(self):
        os.environ.pop("HP_PUBLIC_BASE_URL", None)
        os.environ["HP_PUBLIC_HOST"] = "api-acme.com"
        module = importlib.reload(honeypot_public)
        self.assertEqual(module.HP_PUBLIC_BASE_URL, "https://api-acme.com")

    def test_custom_subdomain_derives_https_base_url(self):
        os.environ.pop("HP_PUBLIC_BASE_URL", None)
        os.environ["HP_PUBLIC_HOST"] = "decoy.customer-authorized.example"
        module = importlib.reload(honeypot_public)
        self.assertEqual(module.HP_PUBLIC_BASE_URL, "https://decoy.customer-authorized.example")

    def test_explicit_public_base_url_still_takes_priority_over_host(self):
        os.environ["HP_PUBLIC_HOST"] = "api-acme.com"
        os.environ["HP_PUBLIC_BASE_URL"] = "https://explicit-override.example"
        module = importlib.reload(honeypot_public)
        self.assertEqual(module.HP_PUBLIC_BASE_URL, "https://explicit-override.example")

    def test_no_host_and_no_base_url_falls_back_to_local_default(self):
        os.environ.pop("HP_PUBLIC_HOST", None)
        os.environ.pop("HP_PUBLIC_BASE_URL", None)
        module = importlib.reload(honeypot_public)
        self.assertEqual(module.HP_PUBLIC_BASE_URL, "http://127.0.0.1:8080")

    def test_trailing_slash_on_host_is_not_duplicated(self):
        os.environ.pop("HP_PUBLIC_BASE_URL", None)
        os.environ["HP_PUBLIC_HOST"] = "api-acme.com/"
        module = importlib.reload(honeypot_public)
        self.assertEqual(module.HP_PUBLIC_BASE_URL, "https://api-acme.com")


if __name__ == "__main__":
    unittest.main()
