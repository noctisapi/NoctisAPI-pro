"""NOC-030: scripts/verify.py.

Everything that touches the network/Docker is mocked, consistent with
test_ops_monitor.py/test_upgrade.py's established pattern. Real
end-to-end verification against a live stack is documented as this
Issue's PR evidence.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.verify as verify  # noqa: E402
from scripts import verify_domain  # noqa: E402


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class _FakeResponse:
    def __init__(self, status=200, url="https://x.invalid/", body=b""):
        self.status = status
        self._url = url
        self._body = body

    def read(self, _n=None):
        return self._body

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestCheckDnsAndTls(unittest.TestCase):
    def test_no_host(self):
        checks = verify.check_dns_and_tls("")
        self.assertFalse(checks[0].ok)

    @patch("scripts.verify.verify_domain.check_tls", return_value="TLS: ok")
    @patch("scripts.verify.verify_domain.resolve_host", return_value=["1.2.3.4"])
    def test_dns_and_tls_pass(self, _mock_resolve, _mock_tls):
        checks = verify.check_dns_and_tls("api.example.com")
        self.assertTrue(all(c.ok for c in checks))
        self.assertEqual(len(checks), 2)

    @patch("scripts.verify.verify_domain.resolve_host", side_effect=verify_domain.CheckFailed("no DNS"))
    def test_dns_failure_skips_tls(self, _mock_resolve):
        checks = verify.check_dns_and_tls("api.example.com")
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0].ok)

    @patch("scripts.verify.verify_domain.check_tls", return_value="TLS: ok")
    @patch("scripts.verify.verify_domain.resolve_host", return_value=["1.2.3.4"])
    def test_expected_ip_mismatch(self, _mock_resolve, _mock_tls):
        checks = verify.check_dns_and_tls("api.example.com", expected_ip="9.9.9.9")
        by_name = {c.name: c for c in checks}
        self.assertFalse(by_name["dns:api.example.com:expected_ip"].ok)


class TestCheckPublicApp(unittest.TestCase):
    def test_no_host(self):
        self.assertFalse(verify.check_public_app("").ok)

    @patch("scripts.verify.urllib.request.urlopen")
    def test_200_passes(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(status=200)
        self.assertTrue(verify.check_public_app("api.example.com").ok)

    @patch("scripts.verify.urllib.request.urlopen", side_effect=urllib.error.HTTPError("u", 500, "err", {}, None))
    def test_http_error_fails(self, _mock):
        check = verify.check_public_app("api.example.com")
        self.assertFalse(check.ok)
        self.assertIn("500", check.detail)

    @patch("scripts.verify.urllib.request.urlopen", side_effect=urllib.error.URLError("boom"))
    def test_connection_error_fails(self, _mock):
        self.assertFalse(verify.check_public_app("api.example.com").ok)


class TestCheckConsole(unittest.TestCase):
    def test_no_admin_host_returns_none(self):
        self.assertIsNone(verify.check_console(""))

    @patch("scripts.verify.urllib.request.urlopen")
    def test_redirect_to_login_is_gated(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(status=200, url="https://admin.example.com/login?next=%2F")
        check = verify.check_console("admin.example.com")
        self.assertTrue(check.ok)

    @patch("scripts.verify.urllib.request.urlopen")
    def test_cloudflare_access_challenge_is_gated(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(
            status=200, url="https://admin.example.com/", body=b"<title>cloudflareaccess challenge</title>"
        )
        check = verify.check_console("admin.example.com")
        self.assertTrue(check.ok)

    def test_401_is_gated(self):
        err = urllib.error.HTTPError("u", 401, "unauthorized", {}, None)
        err.fp = MagicMock()
        err.read = lambda n=None: b""
        err.geturl = lambda: "https://admin.example.com/"
        with patch("scripts.verify.urllib.request.urlopen", side_effect=err):
            check = verify.check_console("admin.example.com")
        self.assertTrue(check.ok)

    @patch("scripts.verify.urllib.request.urlopen")
    def test_bare_200_without_gating_fails(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(status=200, url="https://admin.example.com/", body=b"<h1>Dashboard</h1>")
        check = verify.check_console("admin.example.com")
        self.assertFalse(check.ok)

    @patch("scripts.verify.urllib.request.urlopen")
    def test_502_fails(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(status=502, url="https://admin.example.com/")
        check = verify.check_console("admin.example.com")
        self.assertFalse(check.ok)

    @patch("scripts.verify.urllib.request.urlopen", side_effect=urllib.error.URLError("boom"))
    def test_unreachable_fails(self, _mock):
        check = verify.check_console("admin.example.com")
        self.assertFalse(check.ok)


class TestCheckPermissions(unittest.TestCase):
    def test_skips_missing_secret_files(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.verify.subprocess.run", return_value=_cp(stdout="10001")):
                checks = verify.check_permissions(Path(d), [Path("x.yml")], Path(".env"))
        names = [c.name for c in checks]
        self.assertNotIn("permissions:hp_seed.txt", names)

    @patch("scripts.verify._secret_file_mode", return_value="0o600")
    def test_correct_mode_passes(self, _mock_mode):
        with tempfile.TemporaryDirectory() as d:
            secret = Path(d) / "hp_seed.txt"
            secret.write_text("x")
            with patch("scripts.verify.subprocess.run", return_value=_cp(stdout="10001")):
                checks = verify.check_permissions(Path(d), [Path("x.yml")], Path(".env"))
        by_name = {c.name: c for c in checks}
        self.assertTrue(by_name["permissions:hp_seed.txt"].ok)

    @patch("scripts.verify._secret_file_mode", return_value="0o644")
    def test_wrong_mode_fails(self, _mock_mode):
        with tempfile.TemporaryDirectory() as d:
            secret = Path(d) / "hp_seed.txt"
            secret.write_text("x")
            with patch("scripts.verify.subprocess.run", return_value=_cp(stdout="10001")):
                checks = verify.check_permissions(Path(d), [Path("x.yml")], Path(".env"))
        by_name = {c.name: c for c in checks}
        self.assertFalse(by_name["permissions:hp_seed.txt"].ok)

    def test_correct_uid_passes(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.verify.subprocess.run", return_value=_cp(stdout="10001\n")):
                checks = verify.check_permissions(Path(d), [Path("x.yml")], Path(".env"))
        by_name = {c.name: c for c in checks}
        self.assertTrue(by_name["permissions:app_uid"].ok)
        self.assertTrue(by_name["permissions:admin_uid"].ok)

    def test_wrong_uid_fails(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.verify.subprocess.run", return_value=_cp(stdout="0\n")):
                checks = verify.check_permissions(Path(d), [Path("x.yml")], Path(".env"))
        by_name = {c.name: c for c in checks}
        self.assertFalse(by_name["permissions:app_uid"].ok)


class TestCheckBackups(unittest.TestCase):
    def test_missing_key_and_cron_fail(self):
        with tempfile.TemporaryDirectory() as d:
            secrets_dir = Path(d) / "secrets"
            backup_dir = Path(d) / "backups"
            cron_file = Path(d) / "cron-does-not-exist"
            checks = verify.check_backups(secrets_dir, backup_dir, cron_file)
        self.assertFalse(checks[0].ok)  # encryption_key
        self.assertFalse([c for c in checks if c.name.startswith("backups:cron")][0].ok)

    def test_fresh_install_reports_pending_not_failed(self):
        with tempfile.TemporaryDirectory() as d:
            secrets_dir = Path(d) / "secrets"
            secrets_dir.mkdir()
            (secrets_dir / "backup_encryption_key.txt").write_text("key")
            backup_dir = Path(d) / "backups"
            cron_file = Path(d) / "cron"
            cron_file.write_text("x")
            checks = verify.check_backups(secrets_dir, backup_dir, cron_file)
        freshness = [c for c in checks if c.name == "backups:freshness"][0]
        self.assertTrue(freshness.ok)
        self.assertIn("pending", freshness.detail)

    def test_stale_existing_backup_fails(self):
        import os as _os
        import time as _time
        with tempfile.TemporaryDirectory() as d:
            secrets_dir = Path(d) / "secrets"
            secrets_dir.mkdir()
            (secrets_dir / "backup_encryption_key.txt").write_text("key")
            backup_dir = Path(d) / "backups"
            backup_dir.mkdir()
            stale = backup_dir / "20200101T000000Z-honeypot.db.enc"
            stale.write_text("x")
            old = _time.time() - 48 * 3600
            _os.utime(stale, (old, old))
            cron_file = Path(d) / "cron"
            cron_file.write_text("x")
            checks = verify.check_backups(secrets_dir, backup_dir, cron_file)
        freshness = [c for c in checks if c.name == "backup_freshness"][0]
        self.assertFalse(freshness.ok)


class TestCheckIsolation(unittest.TestCase):
    def test_docker_socket_mounted_fails(self):
        ps_result = _cp(stdout=json.dumps({"Service": "traefik", "ID": "abc123"}) + "\n")
        inspect_mounts = _cp(stdout='[{"Source":"/var/run/docker.sock"}]')

        def side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return ps_result
            if "Mounts" in " ".join(cmd):
                return inspect_mounts
            return _cp(stdout="{}")

        with patch("scripts.verify.subprocess.run", side_effect=side_effect):
            checks = verify.check_isolation([Path("x.yml")], Path(".env"))
        by_name = {c.name: c for c in checks}
        self.assertFalse(by_name["isolation:docker_socket"].ok)

    def test_clean_isolation_passes(self):
        ps_result = _cp(
            stdout="\n".join([
                json.dumps({"Service": "app", "ID": "app1"}),
                json.dumps({"Service": "admin", "ID": "admin1"}),
            ])
        )

        def side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return ps_result
            if "Mounts" in " ".join(cmd):
                return _cp(stdout="[]")
            if "Ports" in " ".join(cmd):
                return _cp(stdout="{}")
            return _cp()

        with patch("scripts.verify.subprocess.run", side_effect=side_effect):
            checks = verify.check_isolation([Path("x.yml")], Path(".env"))
        self.assertTrue(all(c.ok for c in checks))

    def test_admin_published_port_fails(self):
        ps_result = _cp(stdout=json.dumps({"Service": "admin", "ID": "admin1"}))

        def side_effect(cmd, **kwargs):
            if "ps" in cmd:
                return ps_result
            if "Mounts" in " ".join(cmd):
                return _cp(stdout="[]")
            if "Ports" in " ".join(cmd):
                return _cp(stdout='{"9001/tcp":[{"HostPort":"9001"}]}')
            return _cp()

        with patch("scripts.verify.subprocess.run", side_effect=side_effect):
            checks = verify.check_isolation([Path("x.yml")], Path(".env"))
        by_name = {c.name: c for c in checks}
        self.assertFalse(by_name["isolation:admin_no_published_ports"].ok)

    def test_no_containers_fails(self):
        with patch("scripts.verify.subprocess.run", return_value=_cp(stdout="")):
            checks = verify.check_isolation([Path("x.yml")], Path(".env"))
        self.assertFalse(checks[0].ok)


class TestMainIntegration(unittest.TestCase):
    def _argv(self, *extra):
        return ["verify.py"] + list(extra)

    def test_no_host_returns_2(self):
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(verify.main(), 2)

    @patch("scripts.verify.check_isolation", return_value=[])
    @patch("scripts.verify.check_backups", return_value=[])
    @patch("scripts.verify.check_permissions", return_value=[])
    @patch("scripts.verify.ops_monitor.check_containers", return_value=[])
    @patch("scripts.verify.check_console", return_value=None)
    @patch("scripts.verify.check_public_app")
    @patch("scripts.verify.check_dns_and_tls", return_value=[])
    def test_all_passing_exits_zero(
        self, _mock_dns, mock_app, _mock_console, _mock_containers, _mock_perm, _mock_backup, _mock_iso
    ):
        mock_app.return_value = verify.Check("app:x", True, "ok")
        with patch.object(sys, "argv", self._argv("--host", "api.example.com")):
            self.assertEqual(verify.main(), 0)

    @patch("scripts.verify.check_isolation", return_value=[])
    @patch("scripts.verify.check_backups", return_value=[])
    @patch("scripts.verify.check_permissions", return_value=[])
    @patch("scripts.verify.ops_monitor.check_containers", return_value=[])
    @patch("scripts.verify.check_console", return_value=None)
    @patch("scripts.verify.check_public_app")
    @patch("scripts.verify.check_dns_and_tls", return_value=[])
    def test_one_failure_exits_one(
        self, _mock_dns, mock_app, _mock_console, _mock_containers, _mock_perm, _mock_backup, _mock_iso
    ):
        mock_app.return_value = verify.Check("app:x", False, "down")
        with patch.object(sys, "argv", self._argv("--host", "api.example.com")):
            self.assertEqual(verify.main(), 1)

    @patch("scripts.verify.check_isolation", return_value=[])
    @patch("scripts.verify.check_backups", return_value=[])
    @patch("scripts.verify.check_permissions", return_value=[])
    @patch("scripts.verify.ops_monitor.check_containers", return_value=[])
    @patch("scripts.verify.check_console")
    @patch("scripts.verify.check_public_app")
    @patch("scripts.verify.check_dns_and_tls", return_value=[])
    def test_skip_console_never_calls_it(
        self, _mock_dns, mock_app, mock_console, _mock_containers, _mock_perm, _mock_backup, _mock_iso
    ):
        mock_app.return_value = verify.Check("app:x", True, "ok")
        with patch.object(sys, "argv", self._argv("--host", "api.example.com", "--skip-console")):
            verify.main()
        mock_console.assert_not_called()


if __name__ == "__main__":
    unittest.main()
