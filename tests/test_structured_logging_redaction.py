"""NOC-025: structured_logging's redaction safety net for secret-looking
extra= fields.

No current call site actually logs a secret (confirmed by audit), but
these formatters redact by key name regardless -- this is the test for
that safety net itself, not for any specific caller.
"""
from __future__ import annotations

import json
import logging
import unittest

from app.structured_logging import JsonFormatter, TextFormatter, _redact_if_sensitive


class TestRedactIfSensitive(unittest.TestCase):
    def test_known_sensitive_names_are_redacted(self):
        for key in ("hp_seed", "HP_SEED", "seed", "cloudflare_tunnel_token", "token", "secret", "password", "api_key", "private_key"):
            self.assertEqual(_redact_if_sensitive(key, "the-real-value"), "***REDACTED***")

    def test_benign_names_pass_through_unchanged(self):
        for key in ("username", "role", "path", "method", "status_code", "actor_id"):
            self.assertEqual(_redact_if_sensitive(key, "some-value"), "some-value")


def _make_record(**extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="test.logger", level=logging.INFO, pathname=__file__, lineno=1,
        msg="something happened", args=(), exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestJsonFormatterRedacts(unittest.TestCase):
    def test_sensitive_extra_field_is_redacted_in_json_output(self):
        record = _make_record(hp_seed="deadbeef" * 8)
        doc = json.loads(JsonFormatter().format(record))
        self.assertEqual(doc["hp_seed"], "***REDACTED***")

    def test_benign_extra_field_is_not_redacted(self):
        record = _make_record(actor_id="actor-123")
        doc = json.loads(JsonFormatter().format(record))
        self.assertEqual(doc["actor_id"], "actor-123")


class TestTextFormatterRedacts(unittest.TestCase):
    def test_sensitive_extra_field_is_redacted_in_text_output(self):
        record = _make_record(cloudflare_tunnel_token="super-secret-value")
        rendered = TextFormatter().format(record)
        self.assertNotIn("super-secret-value", rendered)
        self.assertIn("REDACTED", rendered)

    def test_benign_extra_field_is_not_redacted(self):
        record = _make_record(actor_id="actor-123")
        rendered = TextFormatter().format(record)
        self.assertIn("actor-123", rendered)


if __name__ == "__main__":
    unittest.main()
