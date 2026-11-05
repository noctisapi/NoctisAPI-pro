"""NOC-028: scripts/ops_monitor.py.

The real checks were run against a real, live Docker stack as this
Issue's verification evidence (see the PR body) -- these tests cover the
parsing/decision logic in isolation with everything mocked, so they can
run anywhere (including Windows dev, where /proc/meminfo and
os.getloadavg() don't exist -- check_memory/check_cpu_load are expected
to return None there, which is exercised directly).
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.ops_monitor as ops_monitor  # noqa: E402


def _compose_ps_result(entries: list) -> subprocess.CompletedProcess:
    stdout = "\n".join(json.dumps(e) for e in entries)
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


class TestCheckContainers(unittest.TestCase):
    @patch("subprocess.run")
    def test_healthy_service_passes(self, mock_run):
        mock_run.return_value = _compose_ps_result(
            [{"Service": "app", "State": "running", "Health": "healthy", "ExitCode": 0}]
        )
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertTrue(checks[0].ok)

    @patch("subprocess.run")
    def test_unhealthy_service_fails(self, mock_run):
        mock_run.return_value = _compose_ps_result(
            [{"Service": "app", "State": "running", "Health": "unhealthy", "ExitCode": 0}]
        )
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertFalse(checks[0].ok)

    @patch("subprocess.run")
    def test_one_shot_service_with_zero_exit_passes(self, mock_run):
        mock_run.return_value = _compose_ps_result(
            [{"Service": "migrate", "State": "exited", "Health": "", "ExitCode": 0}]
        )
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertTrue(checks[0].ok)

    @patch("subprocess.run")
    def test_one_shot_service_with_nonzero_exit_fails(self, mock_run):
        mock_run.return_value = _compose_ps_result(
            [{"Service": "migrate", "State": "exited", "Health": "", "ExitCode": 1}]
        )
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertFalse(checks[0].ok)

    @patch("subprocess.run")
    def test_restarting_service_with_no_reported_health_fails(self, mock_run):
        """The real-world case this test guards: cloudflared crash-looping
        on a bad token reports State=restarting with an EMPTY Health
        field (not "unhealthy") -- confirmed against a real Docker run."""
        mock_run.return_value = _compose_ps_result(
            [{"Service": "cloudflared", "State": "restarting", "Health": "", "ExitCode": 0}]
        )
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertFalse(checks[0].ok)

    @patch("subprocess.run")
    def test_running_service_with_no_healthcheck_passes(self, mock_run):
        mock_run.return_value = _compose_ps_result(
            [{"Service": "something", "State": "running", "Health": "", "ExitCode": 0}]
        )
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertTrue(checks[0].ok)

    @patch("subprocess.run", side_effect=Exception("docker not found"))
    def test_docker_unavailable_is_reported_as_a_failure_not_an_exception(self, _mock):
        checks = ops_monitor.check_containers(Path("x.yml"), Path(".env"))
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0].ok)


class TestCheckDisk(unittest.TestCase):
    @patch("shutil.disk_usage")
    def test_below_threshold_passes(self, mock_disk_usage):
        mock_disk_usage.return_value = MagicMock(total=100, used=50, free=50)
        check = ops_monitor.check_disk(Path("/data"), warn_percent=85.0)
        self.assertTrue(check.ok)

    @patch("shutil.disk_usage")
    def test_above_threshold_fails(self, mock_disk_usage):
        mock_disk_usage.return_value = MagicMock(total=100, used=90, free=10)
        check = ops_monitor.check_disk(Path("/data"), warn_percent=85.0)
        self.assertFalse(check.ok)


class TestCheckMemory(unittest.TestCase):
    def test_returns_none_when_proc_meminfo_is_absent(self):
        with patch("pathlib.Path.exists", return_value=False):
            self.assertIsNone(ops_monitor.check_memory())

    def test_high_usage_fails(self):
        meminfo = "MemTotal: 1000 kB\nMemAvailable: 50 kB\n"
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=meminfo):
            check = ops_monitor.check_memory(warn_percent=90.0)
            self.assertFalse(check.ok)

    def test_low_usage_passes(self):
        meminfo = "MemTotal: 1000 kB\nMemAvailable: 900 kB\n"
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=meminfo):
            check = ops_monitor.check_memory(warn_percent=90.0)
            self.assertTrue(check.ok)


class TestCheckCpuLoad(unittest.TestCase):
    def test_returns_none_on_a_platform_without_getloadavg(self):
        with patch("scripts.ops_monitor.hasattr", return_value=False):
            self.assertIsNone(ops_monitor.check_cpu_load())

    @patch("os.cpu_count", return_value=4)
    def test_high_load_fails(self, _mock_cpu_count):
        with patch("os.getloadavg", return_value=(10.0, 10.0, 10.0), create=True):
            check = ops_monitor.check_cpu_load(warn_ratio=2.0)
            self.assertFalse(check.ok)

    @patch("os.cpu_count", return_value=4)
    def test_low_load_passes(self, _mock_cpu_count):
        with patch("os.getloadavg", return_value=(1.0, 1.0, 1.0), create=True):
            check = ops_monitor.check_cpu_load(warn_ratio=2.0)
            self.assertTrue(check.ok)


class TestCheckCertificate(unittest.TestCase):
    def test_empty_host_returns_none(self):
        self.assertIsNone(ops_monitor.check_certificate(""))

    @patch("scripts.verify_domain.check_tls", return_value="TLS: ok")
    def test_valid_cert_passes(self, _mock):
        check = ops_monitor.check_certificate("example.com")
        self.assertTrue(check.ok)

    @patch("scripts.verify_domain.check_tls")
    def test_failing_cert_fails(self, mock_check_tls):
        from scripts.verify_domain import CheckFailed

        mock_check_tls.side_effect = CheckFailed("expired")
        check = ops_monitor.check_certificate("example.com")
        self.assertFalse(check.ok)


class TestCheckBackupFreshness(unittest.TestCase):
    def test_missing_directory_fails(self):
        check = ops_monitor.check_backup_freshness(Path("/does/not/exist"))
        self.assertFalse(check.ok)

    def test_no_backup_files_fails(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            check = ops_monitor.check_backup_freshness(Path(d))
            self.assertFalse(check.ok)

    def test_fresh_backup_passes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            backup = Path(d) / "20261105T020000Z-honeypot.db.enc"
            backup.write_text("x")
            check = ops_monitor.check_backup_freshness(Path(d), max_age_hours=26.0)
            self.assertTrue(check.ok)

    def test_stale_backup_fails(self):
        import os as _os
        import tempfile
        import time as _time

        with tempfile.TemporaryDirectory() as d:
            backup = Path(d) / "20261101T020000Z-honeypot.db.enc"
            backup.write_text("x")
            old_time = _time.time() - (48 * 3600)
            _os.utime(backup, (old_time, old_time))
            check = ops_monitor.check_backup_freshness(Path(d), max_age_hours=26.0)
            self.assertFalse(check.ok)


class TestSendAlert(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_posts_json_payload_with_failures(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        failures = [ops_monitor.Check("disk:/data", False, "95% used")]
        ops_monitor.send_alert("http://example.invalid/webhook", failures)

        request = mock_urlopen.call_args[0][0]
        payload = json.loads(request.data.decode())
        self.assertEqual(payload["failure_count"], 1)
        self.assertEqual(payload["failures"][0]["check"], "disk:/data")

    @patch("urllib.request.urlopen", side_effect=OSError("connection refused"))
    def test_webhook_failure_does_not_raise(self, _mock):
        failures = [ops_monitor.Check("disk:/data", False, "95% used")]
        ops_monitor.send_alert("http://example.invalid/webhook", failures)  # no raise


class TestMainIntegration(unittest.TestCase):
    @patch("scripts.ops_monitor.check_backup_freshness")
    @patch("scripts.ops_monitor.check_disk")
    @patch("scripts.ops_monitor.check_containers")
    def test_all_passing_exits_zero(self, mock_containers, mock_disk, mock_backup):
        mock_containers.return_value = [ops_monitor.Check("container:app", True, "ok")]
        mock_disk.return_value = ops_monitor.Check("disk", True, "ok")
        mock_backup.return_value = ops_monitor.Check("backup_freshness", True, "ok")
        with patch.object(
            sys, "argv",
            ["ops_monitor.py", "--skip-certificate"],
        ):
            self.assertEqual(ops_monitor.main(), 0)

    @patch("scripts.ops_monitor.check_backup_freshness")
    @patch("scripts.ops_monitor.check_disk")
    @patch("scripts.ops_monitor.check_containers")
    def test_one_failure_exits_nonzero(self, mock_containers, mock_disk, mock_backup):
        mock_containers.return_value = [ops_monitor.Check("container:app", False, "unhealthy")]
        mock_disk.return_value = ops_monitor.Check("disk", True, "ok")
        mock_backup.return_value = ops_monitor.Check("backup_freshness", True, "ok")
        with patch.object(sys, "argv", ["ops_monitor.py", "--skip-certificate"]):
            self.assertEqual(ops_monitor.main(), 1)

    @patch("scripts.ops_monitor.send_alert")
    @patch("scripts.ops_monitor.check_backup_freshness")
    @patch("scripts.ops_monitor.check_disk")
    @patch("scripts.ops_monitor.check_containers")
    def test_webhook_is_called_on_failure_when_configured(
        self, mock_containers, mock_disk, mock_backup, mock_send_alert
    ):
        mock_containers.return_value = [ops_monitor.Check("container:app", False, "unhealthy")]
        mock_disk.return_value = ops_monitor.Check("disk", True, "ok")
        mock_backup.return_value = ops_monitor.Check("backup_freshness", True, "ok")
        with patch.dict("os.environ", {"HP_OPS_ALERT_WEBHOOK_URL": "http://example.invalid/hook"}):
            with patch.object(sys, "argv", ["ops_monitor.py", "--skip-certificate"]):
                ops_monitor.main()
        mock_send_alert.assert_called_once()

    @patch("scripts.ops_monitor.send_alert")
    @patch("scripts.ops_monitor.check_backup_freshness")
    @patch("scripts.ops_monitor.check_disk")
    @patch("scripts.ops_monitor.check_containers")
    def test_webhook_is_not_called_on_success(self, mock_containers, mock_disk, mock_backup, mock_send_alert):
        mock_containers.return_value = [ops_monitor.Check("container:app", True, "ok")]
        mock_disk.return_value = ops_monitor.Check("disk", True, "ok")
        mock_backup.return_value = ops_monitor.Check("backup_freshness", True, "ok")
        with patch.dict("os.environ", {"HP_OPS_ALERT_WEBHOOK_URL": "http://example.invalid/hook"}):
            with patch.object(sys, "argv", ["ops_monitor.py", "--skip-certificate"]):
                ops_monitor.main()
        mock_send_alert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
