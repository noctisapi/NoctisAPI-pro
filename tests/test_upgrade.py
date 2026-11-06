"""NOC-029: scripts/upgrade.py.

Everything that touches Docker is mocked -- real end-to-end verification
(a genuine upgrade, a genuine migration-failure rollback, and a genuine
health-check-failure rollback against a live stack) was run manually as
this Issue's verification evidence, per the PR body, the same split
established by test_ops_monitor.py/test_dr_drill.py.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.upgrade as upgrade  # noqa: E402


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestRunningImage(unittest.TestCase):
    @patch("scripts.upgrade._run")
    def test_parses_the_running_container_image(self, mock_run):
        mock_run.return_value = _cp(stdout=json.dumps({"Service": "app", "Image": "repo/app:1.0.0"}) + "\n")
        image = upgrade.running_image([Path("x.yml")], Path(".env"), "app")
        self.assertEqual(image, "repo/app:1.0.0")

    @patch("scripts.upgrade._run")
    def test_returns_none_when_nothing_is_running(self, mock_run):
        mock_run.return_value = _cp(stdout="")
        self.assertIsNone(upgrade.running_image([Path("x.yml")], Path(".env"), "app"))


class TestTargetImage(unittest.TestCase):
    @patch("scripts.upgrade.compose_config")
    def test_reads_the_resolved_image_from_compose_config(self, mock_config):
        mock_config.return_value = {"services": {"app": {"image": "repo/app:2.0.0"}}}
        self.assertEqual(upgrade.target_image([Path("x.yml")], Path(".env"), "app"), "repo/app:2.0.0")


class TestApprovedTarget(unittest.TestCase):
    def test_accepts_exact_or_tagged_image(self):
        self.assertTrue(upgrade.approved_target("repo/app:2.0.0", "2.0.0"))
        self.assertTrue(upgrade.approved_target("repo/app@sha256:abc", "repo/app@sha256:abc"))

    def test_rejects_latest_or_mismatched_tag(self):
        self.assertFalse(upgrade.approved_target("repo/app:latest", "latest"))
        self.assertFalse(upgrade.approved_target("repo/app:2.0.0", "2.1.0"))


class TestResolveDigest(unittest.TestCase):
    @patch("scripts.upgrade._run")
    def test_returns_digest_when_available(self, mock_run):
        mock_run.return_value = _cp(stdout="repo/app@sha256:abc123\n")
        self.assertEqual(upgrade.resolve_digest("repo/app:2.0.0"), "repo/app@sha256:abc123")

    @patch("scripts.upgrade._run")
    def test_returns_empty_string_when_unavailable(self, mock_run):
        mock_run.return_value = _cp(returncode=1, stdout="")
        self.assertEqual(upgrade.resolve_digest("repo/app:local"), "")


class TestCurrentRevision(unittest.TestCase):
    @patch("scripts.upgrade._run")
    def test_parses_current_revision_from_status_checks(self, mock_run):
        mock_run.return_value = _cp(stdout=json.dumps({"current_revision": "abc123", "expected_revision": "abc123"}))
        self.assertEqual(upgrade.current_revision([Path("x.yml")], Path(".env"), "app"), "abc123")

    @patch("scripts.upgrade._run")
    def test_returns_none_on_failure(self, mock_run):
        mock_run.return_value = _cp(returncode=1, stdout="")
        self.assertIsNone(upgrade.current_revision([Path("x.yml")], Path(".env"), "app"))


class TestPendingMigrations(unittest.TestCase):
    @patch("scripts.upgrade._run")
    def test_parses_pending_migrations_json(self, mock_run):
        mock_run.return_value = _cp(stdout=json.dumps([
            {"revision": "r2", "irreversible": False, "reason": ""},
            {"revision": "r3", "irreversible": True, "reason": "drops a column"},
        ]))
        pending = upgrade.pending_migrations("repo/app:2.0.0", "r1")
        self.assertEqual(len(pending), 2)
        self.assertTrue(pending[1]["irreversible"])

    @patch("scripts.upgrade._run")
    def test_raises_on_introspection_failure(self, mock_run):
        mock_run.return_value = _cp(returncode=1, stderr="boom")
        with self.assertRaises(upgrade.UpgradeFailed):
            upgrade.pending_migrations("repo/app:2.0.0", "r1")


class TestIrreversibleGate(unittest.TestCase):
    def test_no_pending_passes(self):
        self.assertIsNone(upgrade.irreversible_gate([], force=False))

    def test_only_reversible_passes(self):
        pending = [{"revision": "r2", "irreversible": False, "reason": ""}]
        self.assertIsNone(upgrade.irreversible_gate(pending, force=False))

    def test_irreversible_without_force_aborts(self):
        pending = [{"revision": "r3", "irreversible": True, "reason": "drops a column"}]
        message = upgrade.irreversible_gate(pending, force=False)
        self.assertIsNotNone(message)
        self.assertIn("r3", message)
        self.assertIn("drops a column", message)

    def test_irreversible_with_force_passes(self):
        pending = [{"revision": "r3", "irreversible": True, "reason": "drops a column"}]
        self.assertIsNone(upgrade.irreversible_gate(pending, force=True))


class TestRunBackup(unittest.TestCase):
    @patch("scripts.upgrade._run")
    @patch("scripts.upgrade.resolved_volumes")
    def test_produces_encrypted_db_and_myapp_backups(self, mock_resolved, mock_run):
        mock_resolved.return_value = {
            "data_volume": "proj_hp_prod_data", "myapp_volume": "proj_hp_prod_myapp", "app_image": "repo/app:2.0.0",
        }
        import re as _re
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            backup_dir = Path(d)

            def fake_run(cmd, **kwargs):
                # Stand in for `docker run` actually writing into backup_dir
                # (mounted as /backups inside the container).
                for part in cmd:
                    for m in _re.finditer(r"/backups/([\w.\-]+)", str(part)):
                        (backup_dir / m.group(1)).touch()
                return _cp()

            mock_run.side_effect = fake_run
            backups = upgrade.run_backup([Path("x.yml")], Path(".env"), backup_dir)
            self.assertTrue(str(backups["db"]).endswith("-honeypot.db.enc"))
            self.assertTrue(str(backups["myapp"]).endswith("-myapp.tar.enc"))
            # sqlite backup, tar, then one encrypt call per artifact
            self.assertEqual(mock_run.call_count, 4)
            encrypt_calls = [c for c in mock_run.call_args_list if "encrypt" in c.args[0]]
            self.assertEqual(len(encrypt_calls), 2)
            for c in encrypt_calls:
                self.assertIn("repo/app:2.0.0", c.args[0])


class TestAssertVolumeNotInUse(unittest.TestCase):
    @patch("scripts.upgrade._run")
    def test_passes_when_volume_is_free(self, mock_run):
        mock_run.return_value = _cp(stdout="")
        upgrade._assert_volume_not_in_use("vol")  # no raise

    @patch("scripts.upgrade._run")
    def test_raises_when_volume_is_in_use(self, mock_run):
        mock_run.return_value = _cp(stdout="abcdef123456\n")
        with self.assertRaises(upgrade.UpgradeFailed):
            upgrade._assert_volume_not_in_use("vol")


class TestRestoreBackup(unittest.TestCase):
    @patch("scripts.upgrade._run")
    def test_decrypts_and_restores_db(self, mock_run):
        mock_run.return_value = _cp(stdout="")  # also satisfies the not-in-use check
        upgrade.restore_backup(
            Path(".env.prod"), "db", Path("/b/backup.db.enc"), volume="proj_hp_prod_data", app_image="repo/app:1.0.0"
        )
        decrypt_calls = [c for c in mock_run.call_args_list if "decrypt" in c.args[0]]
        self.assertEqual(len(decrypt_calls), 1)
        self.assertIn("repo/app:1.0.0", decrypt_calls[0].args[0])
        cp_calls = [c for c in mock_run.call_args_list if "cp" in c.args[0]]
        self.assertEqual(len(cp_calls), 1)

    @patch("scripts.upgrade._run")
    def test_refuses_when_volume_in_use(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[:2] == ["docker", "ps"]:
                return _cp(stdout="abcdef123456\n")
            return _cp()

        mock_run.side_effect = side_effect
        with self.assertRaises(upgrade.UpgradeFailed):
            upgrade.restore_backup(
                Path(".env.prod"), "db", Path("/b/backup.db.enc"),
                volume="proj_hp_prod_data", app_image="repo/app:1.0.0",
            )


class TestWaitHealthy(unittest.TestCase):
    @patch("scripts.upgrade.ops_monitor.check_containers")
    def test_returns_true_when_relevant_services_are_healthy(self, mock_check):
        mock_check.return_value = [
            upgrade.ops_monitor.Check("container:app", True, "ok"),
            upgrade.ops_monitor.Check("container:admin", True, "ok"),
        ]
        self.assertTrue(upgrade.wait_healthy([Path("x.yml")], Path(".env"), timeout=5))

    @patch("scripts.upgrade.ops_monitor.check_containers")
    def test_returns_false_on_timeout(self, mock_check):
        mock_check.return_value = [upgrade.ops_monitor.Check("container:app", False, "unhealthy")]
        self.assertFalse(upgrade.wait_healthy([Path("x.yml")], Path(".env"), timeout=0))


class TestRecordUpgrade(unittest.TestCase):
    def test_success_records_app_image_and_history(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest_path = Path(d) / "deployment-manifest.json"
            manifest = upgrade.record_upgrade(
                manifest_path, previous_image="repo/app:1.0.0", new_image="repo/app:2.0.0",
                digest="repo/app@sha256:abc", result="success",
            )
            self.assertEqual(manifest["app_image"], "repo/app:2.0.0")
            self.assertEqual(manifest["previous_app_image"], "repo/app:1.0.0")
            self.assertEqual(manifest["app_image_digest"], "repo/app@sha256:abc")
            self.assertEqual(len(manifest["upgrade_history"]), 1)
            self.assertEqual(manifest["upgrade_history"][0]["result"], "success")

    def test_stamps_schema_version_and_status_even_on_a_brand_new_manifest(self):
        """NOC-031: upgrade.py can be the very first writer of this
        manifest (no prior init_deployment.py run) -- it must still end
        up schema-compliant."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest_path = Path(d) / "deployment-manifest.json"
            manifest = upgrade.record_upgrade(
                manifest_path, previous_image="repo/app:1.0.0", new_image="repo/app:2.0.0",
                digest="", result="success",
            )
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["status"], "active")

    def test_rolled_back_does_not_overwrite_app_image(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest_path = Path(d) / "deployment-manifest.json"
            upgrade.record_upgrade(
                manifest_path, previous_image="repo/app:1.0.0", new_image="repo/app:1.0.0",
                digest="", result="success",
            )
            manifest = upgrade.record_upgrade(
                manifest_path, previous_image="repo/app:1.0.0", new_image="repo/app:2.0.0",
                digest="", result="rolled_back", reason="migration failed",
            )
            self.assertEqual(manifest["app_image"], "repo/app:1.0.0")
            self.assertEqual(len(manifest["upgrade_history"]), 2)
            self.assertEqual(manifest["upgrade_history"][-1]["reason"], "migration failed")

    def test_history_is_capped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            manifest_path = Path(d) / "deployment-manifest.json"
            manifest = {}
            for i in range(25):
                manifest = upgrade.record_upgrade(
                    manifest_path, previous_image=f"repo/app:{i}", new_image=f"repo/app:{i + 1}",
                    digest="", result="success",
                )
            self.assertLessEqual(len(manifest["upgrade_history"]), 20)


class TestRollback(unittest.TestCase):
    def _resolved(self):
        return {"data_volume": "proj_data", "myapp_volume": "proj_myapp", "app_image": "repo/app:2.0.0"}

    @patch("scripts.upgrade.record_upgrade")
    @patch("scripts.upgrade.wait_healthy", return_value=True)
    @patch("scripts.upgrade.restore_backup")
    @patch("scripts.upgrade.resolved_volumes")
    @patch("scripts.upgrade._run")
    def test_restores_backup_and_reverts_image(self, mock_run, mock_resolved, mock_restore, mock_wait, mock_record):
        mock_run.return_value = _cp()
        mock_resolved.return_value = self._resolved()
        backups = {"db": Path("/b/db.enc"), "myapp": Path("/b/myapp.enc")}
        code = upgrade._rollback(
            [Path("x.yml")], Path(".env"), previous_image="repo/app:1.0.0", new_image="repo/app:2.0.0",
            backups=backups, manifest_path=Path("/m.json"), reason="migration failed",
        )
        self.assertEqual(code, 1)
        self.assertEqual(mock_restore.call_count, 2)
        for c in mock_restore.call_args_list:
            self.assertEqual(c.kwargs["app_image"], "repo/app:1.0.0")  # restores using the PREVIOUS, known-good image
        mock_record.assert_called_once()
        self.assertEqual(mock_record.call_args.kwargs["result"], "rolled_back")
        up_call = [c for c in mock_run.call_args_list if "up" in c.args[0]][-1]
        self.assertEqual(up_call.kwargs["env"]["APP_VERSION"], "1.0.0")

    @patch("scripts.upgrade.record_upgrade")
    @patch("scripts.upgrade.wait_healthy", return_value=True)
    @patch("scripts.upgrade.restore_backup")
    @patch("scripts.upgrade.resolved_volumes")
    @patch("scripts.upgrade._run")
    def test_skips_restore_when_no_backup_was_taken(self, mock_run, mock_resolved, mock_restore, mock_wait, mock_record):
        mock_run.return_value = _cp()
        mock_resolved.return_value = self._resolved()
        code = upgrade._rollback(
            [Path("x.yml")], Path(".env"), previous_image="repo/app:1.0.0", new_image="repo/app:2.0.0",
            backups=None, manifest_path=Path("/m.json"), reason="health check failed",
        )
        self.assertEqual(code, 1)
        mock_restore.assert_not_called()


class TestMainIntegration(unittest.TestCase):
    def _argv(self, *extra):
        return ["upgrade.py"] + list(extra)

    @patch("scripts.upgrade.running_image", return_value=None)
    def test_nothing_running_aborts(self, _mock):
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 2)

    @patch("scripts.upgrade.target_image", return_value="repo/app:1.0.0")
    @patch("scripts.upgrade.running_image", return_value="repo/app:1.0.0")
    def test_already_up_to_date_is_a_noop(self, _mock_running, _mock_target):
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 0)

    @patch("scripts.upgrade.run_backup")
    @patch("scripts.upgrade.current_revision", return_value="r1")
    @patch("scripts.upgrade.pending_migrations")
    @patch("scripts.upgrade.target_image", return_value="repo/app:2.0.0")
    @patch("scripts.upgrade.running_image", return_value="repo/app:1.0.0")
    def test_irreversible_migration_aborts_before_any_backup(
        self, _mock_running, _mock_target, mock_pending, _mock_rev, mock_backup
    ):
        mock_pending.return_value = [{"revision": "r2", "irreversible": True, "reason": "drops data"}]
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 2)
        mock_backup.assert_not_called()

    @patch("scripts.upgrade._rollback")
    @patch("scripts.upgrade.run_backup", return_value={"db": Path("d"), "myapp": Path("m")})
    @patch("scripts.upgrade.current_revision", return_value=None)
    @patch("scripts.upgrade.target_image", return_value="repo/app:2.0.0")
    @patch("scripts.upgrade.running_image", return_value="repo/app:1.0.0")
    @patch("scripts.upgrade._run", side_effect=upgrade.UpgradeFailed("registry unreachable"))
    def test_pull_failure_aborts_without_rollback(
        self, _mock_run, _mock_running, _mock_target, _mock_rev, mock_backup, mock_rollback
    ):
        """A pull failure happens before anything was switched -- the
        previous version never stopped, so there is nothing to roll back
        (and raising an unhandled exception here would be a bug, not a
        clean operator-facing failure)."""
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 2)
        mock_rollback.assert_not_called()

    @patch("scripts.upgrade._rollback", return_value=1)
    @patch("scripts.upgrade.run_backup", return_value={"db": Path("d"), "myapp": Path("m")})
    @patch("scripts.upgrade.current_revision", return_value=None)
    @patch("scripts.upgrade.target_image", return_value="repo/app:2.0.0")
    @patch("scripts.upgrade.running_image", return_value="repo/app:1.0.0")
    @patch("scripts.upgrade._run")
    def test_migration_failure_triggers_rollback(
        self, mock_run, _mock_running, _mock_target, _mock_rev, mock_backup, mock_rollback
    ):
        def run_side_effect(cmd, **kwargs):
            if "migrate" in cmd and "--exit-code-from" in cmd:
                return _cp(returncode=1, stderr="migration exploded")
            return _cp()

        mock_run.side_effect = run_side_effect
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 1)
        mock_rollback.assert_called_once()
        self.assertEqual(mock_rollback.call_args.kwargs["reason"], "migration failed")

    @patch("scripts.upgrade._rollback", return_value=1)
    @patch("scripts.upgrade.wait_healthy", return_value=False)
    @patch("scripts.upgrade.run_backup", return_value={"db": Path("d"), "myapp": Path("m")})
    @patch("scripts.upgrade.current_revision", return_value=None)
    @patch("scripts.upgrade.target_image", return_value="repo/app:2.0.0")
    @patch("scripts.upgrade.running_image", return_value="repo/app:1.0.0")
    @patch("scripts.upgrade._run", return_value=_cp())
    def test_health_check_failure_triggers_rollback(
        self, _mock_run, _mock_running, _mock_target, _mock_rev, mock_backup, mock_wait, mock_rollback
    ):
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 1)
        mock_rollback.assert_called_once()
        self.assertEqual(mock_rollback.call_args.kwargs["reason"], "post-upgrade health check failed")

    @patch("scripts.upgrade.record_upgrade")
    @patch("scripts.upgrade.resolve_digest", return_value="repo/app@sha256:abc")
    @patch("scripts.upgrade.wait_healthy", return_value=True)
    @patch("scripts.upgrade.run_backup", return_value={"db": Path("d"), "myapp": Path("m")})
    @patch("scripts.upgrade.current_revision", return_value=None)
    @patch("scripts.upgrade.target_image", return_value="repo/app:2.0.0")
    @patch("scripts.upgrade.running_image", return_value="repo/app:1.0.0")
    @patch("scripts.upgrade._run", return_value=_cp())
    def test_successful_upgrade_records_the_manifest(
        self, _mock_run, _mock_running, _mock_target, _mock_rev, mock_backup, mock_wait, mock_digest, mock_record
    ):
        with patch.object(sys, "argv", self._argv()):
            self.assertEqual(upgrade.main(), 0)
        mock_record.assert_called_once()
        self.assertEqual(mock_record.call_args.kwargs["result"], "success")
        self.assertEqual(mock_record.call_args.kwargs["new_image"], "repo/app:2.0.0")


if __name__ == "__main__":
    unittest.main()
