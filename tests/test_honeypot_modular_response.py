import asyncio
import json
import unittest

from starlette.requests import Request
from starlette.responses import StreamingResponse

from app.honeypot_public import _apply_modular_response_policy


def _request(path: str = "/config.json", method: str = "GET", headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": headers or [(b"host", b"testserver"), (b"user-agent", b"test-agent")],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


class TestHoneypotModularResponse(unittest.TestCase):
    def test_streaming_json_is_mutated_in_minimal_mode(self):
        async def body():
            yield b'{"service":"platform-api","region":"eu-west-1","contact":{"support":"x@y.z"}}'

        response = StreamingResponse(body(), media_type="application/json", status_code=200)
        policy = {
            "endpoint_config": {
                "enabled": True,
                "response_mode": "minimal",
                "fixed_status": None,
                "richness_level": 0,
            },
            "endpoint_match_type": "exact",
            "rules": {"matched_rule_ids": []},
            "mutation": {"mutation_policy": "none", "mutation_intensity": 0},
        }

        out = asyncio.run(_apply_modular_response_policy(_request(), response, policy))
        payload = json.loads((out.body or b"{}").decode("utf-8", errors="ignore"))
        self.assertEqual(out.status_code, 200)
        self.assertEqual(payload, {"ok": True})

    def test_streaming_text_is_mutated_in_minimal_mode(self):
        async def body():
            yield b"APP_ENV=production\nDB_HOST=10.0.0.1\nJWT_SECRET=secret\n"

        response = StreamingResponse(body(), media_type="text/plain", status_code=200)
        policy = {
            "endpoint_config": {
                "enabled": True,
                "response_mode": "minimal",
                "fixed_status": None,
                "richness_level": 0,
            },
            "endpoint_match_type": "exact",
            "rules": {"matched_rule_ids": []},
            "mutation": {"mutation_policy": "none", "mutation_intensity": 0},
        }

        out = asyncio.run(_apply_modular_response_policy(_request(path="/.env"), response, policy))
        self.assertEqual(out.status_code, 200)
        self.assertEqual((out.body or b"").decode("utf-8", errors="ignore"), "status=ok\n")


if __name__ == "__main__":
    unittest.main()
