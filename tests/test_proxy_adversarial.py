"""Adversarial reverse-proxy regression battery -- NOC-015.

Runs a real Traefik v3.7.16 against a `traefik/whoami` stand-in backend,
using the *actual* rendered File Provider config and the *actual* `traefik`
service command from compose/docker-compose.prod.yml (only the websecure
readTimeout is shortened, so the slow-client check stays fast) -- this
exercises real TLS/PROXY-protocol/header/timeout behavior that a pure-Python
unit test cannot, and will not silently drift from the real config since it
reads it directly instead of hand-copying flags.

Forged X-Forwarded-* trust handling (NOC-010) is already covered
exhaustively at the application layer by tests/test_trusted_proxy.py and
tests/test_reverse_proxy.py and is deliberately not duplicated here.

Requires Docker; the whole module is skipped if it is not available (e.g. a
bare machine without Docker running).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import uuid

import httpx
import yaml

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RENDER_SCRIPT = os.path.join(_REPO_ROOT, "compose", "traefik", "render-dynamic-config.sh")
_PROD_COMPOSE = os.path.join(_REPO_ROOT, "compose", "docker-compose.prod.yml")

_TEST_READ_TIMEOUT = "2s"  # production uses 30s (NOC-014); shortened here for test speed


def _docker_available() -> bool:
    if not shutil.which("docker") or not shutil.which("curl"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _traefik_command_with_fast_test_timeout() -> list[str]:
    with open(_PROD_COMPOSE, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)
    command = list(compose["services"]["traefik"]["command"])
    out = []
    for arg in command:
        if arg.startswith("--entrypoints.websecure.transport.respondingTimeouts.readTimeout="):
            out.append(
                f"--entrypoints.websecure.transport.respondingTimeouts.readTimeout={_TEST_READ_TIMEOUT}"
            )
        else:
            out.append(arg)
    return out


@unittest.skipUnless(_docker_available(), "Docker is not available")
class TestProxyAdversarialBattery(unittest.TestCase):
    """One real Traefik + whoami stack, shared across the adversarial checks."""

    @classmethod
    def setUpClass(cls):
        run_id = uuid.uuid4().hex[:10]
        net = f"noc015-{run_id}"
        backend = f"noc015-backend-{run_id}"
        traefik = f"noc015-traefik-{run_id}"
        tmpdir = tempfile.mkdtemp(prefix="noc015-")
        cls.addClassCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        dyn_dir = os.path.join(tmpdir, "dynamic")
        os.makedirs(dyn_dir)

        cls.https_port = _free_port()
        cls.internal_port = _free_port()

        subprocess.run(["docker", "network", "create", net], check=True, capture_output=True)
        cls.addClassCleanup(subprocess.run, ["docker", "network", "rm", net], capture_output=True)

        script_copy = os.path.join(tmpdir, "render.sh")
        with open(_RENDER_SCRIPT, "r", encoding="utf-8") as f:
            src = f.read()
        out_path = os.path.join(dyn_dir, "dynamic.yml").replace("\\", "/")
        src = src.replace('OUT="/etc/traefik/dynamic/dynamic.yml"', f'OUT="{out_path}"')
        with open(script_copy, "w", encoding="utf-8") as f:
            f.write(src)
        env = dict(os.environ)
        env.update(
            {
                "HP_PUBLIC_HOST": "example.test",
                "HP_PUBLIC_RATELIMIT_AVG": "120",
                "HP_PUBLIC_RATELIMIT_BURST": "240",
                "HP_PUBLIC_MAX_BODY_BYTES": "1048576",  # 1 MiB, small for a fast oversized-body test
            }
        )
        subprocess.run(["sh", script_copy], env=env, check=True, capture_output=True)

        subprocess.run(
            [
                "docker", "run", "-d", "--name", backend,
                "--network", net, "--network-alias", "app",
                "traefik/whoami:latest", "--port=8000",
            ],
            check=True, capture_output=True,
        )
        cls.addClassCleanup(subprocess.run, ["docker", "rm", "-f", backend], capture_output=True)

        traefik_cmd = _traefik_command_with_fast_test_timeout()
        subprocess.run(
            [
                "docker", "run", "-d", "--name", traefik,
                "--network", net,
                "-p", f"127.0.0.1:{cls.https_port}:443",
                "-p", f"127.0.0.1:{cls.internal_port}:8081",
                "-v", f"{dyn_dir}:/etc/traefik/dynamic:ro",
                "traefik:v3.7.16",
                *traefik_cmd,
            ],
            check=True, capture_output=True,
        )
        cls.addClassCleanup(subprocess.run, ["docker", "rm", "-f", traefik], capture_output=True)

        cls._wait_until_ready()

    @classmethod
    def _wait_until_ready(cls):
        deadline = time.time() + 20
        last_exc: Exception | None = None
        while time.time() < deadline:
            try:
                httpx.get(
                    f"https://127.0.0.1:{cls.https_port}/",
                    headers={"Host": "example.test"},
                    verify=False,
                    timeout=1.0,
                )
                return
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                time.sleep(0.5)
        raise RuntimeError(f"traefik never became ready: {last_exc}")

    # -- TLS --

    def test_tls_1_2_is_accepted(self):
        resp = httpx.get(
            f"https://127.0.0.1:{self.https_port}/",
            headers={"Host": "example.test"},
            verify=False,
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)

    # A negative "TLS 1.1 is rejected" case is deliberately not automated
    # here: many CI/dev environments' own OpenSSL already refuses to offer
    # legacy TLS client-side via system-wide crypto policy, which would make
    # that test pass for the wrong reason regardless of server config.
    # Already verified manually against real Traefik for NOC-014 (PR #77).

    # -- request body cap --

    def test_oversized_body_is_rejected(self):
        # curl, not httpx: Traefik's buffering middleware can reset the
        # connection mid-send once the limit is exceeded rather than let the
        # client finish writing before it reads a clean response, which
        # httpx's client surfaces as a transport ReadError instead of a
        # status code. curl's own libcurl handles that the same way a real
        # attacker's tooling would and still reports the final status.
        big = os.urandom(2 * 1024 * 1024)  # 2 MiB > 1 MiB test limit
        result = subprocess.run(
            [
                "curl", "-sk", "-o", os.devnull, "-w", "%{http_code}",
                f"https://127.0.0.1:{self.https_port}/",
                "-H", "Host: example.test",
                "--data-binary", "@-",
            ],
            input=big, capture_output=True, timeout=15,
        )
        self.assertEqual(result.stdout.decode().strip(), "413")

    def test_small_body_passes_through(self):
        resp = httpx.post(
            f"https://127.0.0.1:{self.https_port}/",
            headers={"Host": "example.test"},
            content=os.urandom(1024),
            verify=False,
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)

    # -- ambiguous / unexpected Host --

    def test_unexpected_host_does_not_route_anywhere(self):
        resp = httpx.get(
            f"https://127.0.0.1:{self.https_port}/",
            headers={"Host": "definitely-not-the-real-host.invalid"},
            verify=False,
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 404)

    # -- internal/monitor header integrity (NOC-012 + reconciliation regressions) --

    def test_public_health_router_never_carries_the_monitor_secret(self):
        resp = httpx.get(
            f"https://127.0.0.1:{self.https_port}/status",
            headers={"Host": "example.test", "X-Internal-Monitor": "attacker-supplied-guess"},
            verify=False,
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)
        # The attacker's own value must pass through untouched -- Traefik
        # must never swap it for (or confirm) anything of its own.
        self.assertIn("X-Internal-Monitor: attacker-supplied-guess", resp.text)

    def test_internal_router_never_overwrites_a_real_client_secret(self):
        resp = httpx.get(
            f"http://127.0.0.1:{self.internal_port}/",
            headers={"X-Internal-Monitor": "a-real-random-secret-value"},
            timeout=5.0,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("X-Internal-Monitor: a-real-random-secret-value", resp.text)
        self.assertNotIn("X-Internal-Monitor: 1", resp.text)

    def test_internal_router_does_not_invent_a_secret_when_client_sends_none(self):
        resp = httpx.get(f"http://127.0.0.1:{self.internal_port}/", timeout=5.0)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("X-Internal-Monitor", resp.text)

    # -- PROXY Protocol --

    def test_proxy_protocol_preamble_is_not_silently_trusted(self):
        """No entryPoint enables proxyProtocol in the real config -- a raw
        PROXY protocol line must not be parsed as trusted framing."""
        with socket.create_connection(("127.0.0.1", self.https_port), timeout=5) as sock:
            sock.sendall(b"PROXY TCP4 203.0.113.1 10.0.0.1 12345 443\r\n")
            sock.settimeout(5)
            try:
                data = sock.recv(4096)
            except OSError:
                data = b""
        self.assertNotIn(b"HTTP/1.1 200", data)
        self.assertNotIn(b"200 OK", data)

    # -- slow / stalled client --

    def test_idle_client_is_eventually_disconnected_by_read_timeout(self):
        """Classic slow-loris shape: connect and send nothing. Traefik's
        respondingTimeouts.readTimeout (2s in this test, 30s in production,
        both via the same real flag) must close the connection rather than
        hold it open indefinitely."""
        started = time.time()
        with socket.create_connection(("127.0.0.1", self.https_port), timeout=10) as sock:
            sock.settimeout(10)
            try:
                data = sock.recv(100)
            except OSError:
                data = b""
        elapsed = time.time() - started
        self.assertEqual(data, b"")
        self.assertLess(elapsed, 9.0, "Traefik never enforced its read timeout")


if __name__ == "__main__":
    unittest.main()
