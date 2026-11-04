import asyncio
import json
import unittest

from starlette.requests import Request
from starlette.responses import StreamingResponse

from app.honeypot_public import _apply_modular_response_policy


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


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

        out = _run(_apply_modular_response_policy(_request(), response, policy))
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

        out = _run(_apply_modular_response_policy(_request(path="/.env"), response, policy))
        self.assertEqual(out.status_code, 200)
        self.assertEqual((out.body or b"").decode("utf-8", errors="ignore"), "status=ok\n")

    def test_streaming_text_normal_mode_respects_richness(self):
        async def body():
            yield b"L1\nL2\nL3\nL4\nL5\nL6\n"

        base_policy = {
            "endpoint_config": {
                "enabled": True,
                "response_mode": "normal",
                "fixed_status": None,
                "richness_level": 2,
            },
            "endpoint_match_type": "exact",
            "rules": {"matched_rule_ids": []},
            "mutation": {"mutation_policy": "none", "mutation_intensity": 0},
        }

        response_full = StreamingResponse(body(), media_type="text/plain", status_code=200)
        out_full = _run(_apply_modular_response_policy(_request(path="/.env"), response_full, base_policy))
        self.assertEqual((out_full.body or b"").decode("utf-8", errors="ignore"), "L1\nL2\nL3\nL4\nL5\nL6\n")

        policy_mid = dict(base_policy)
        policy_mid["endpoint_config"] = dict(base_policy["endpoint_config"])
        policy_mid["endpoint_config"]["richness_level"] = 1
        response_mid = StreamingResponse(body(), media_type="text/plain", status_code=200)
        out_mid = _run(_apply_modular_response_policy(_request(path="/.env"), response_mid, policy_mid))
        self.assertEqual((out_mid.body or b"").decode("utf-8", errors="ignore"), "L1\nL2\nL3\nL4\nL5\n")

        policy_low = dict(base_policy)
        policy_low["endpoint_config"] = dict(base_policy["endpoint_config"])
        policy_low["endpoint_config"]["richness_level"] = 0
        response_low = StreamingResponse(body(), media_type="text/plain", status_code=200)
        out_low = _run(_apply_modular_response_policy(_request(path="/.env"), response_low, policy_low))
        self.assertEqual((out_low.body or b"").decode("utf-8", errors="ignore"), "L1\n")


if __name__ == "__main__":
    unittest.main()
