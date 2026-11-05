"""NOC-025/NOC-026: scripts/init_deployment.py -- per-deployment secret
generation (HP_SEED, the backup encryption key) and the non-secret
deployment manifest.

Uses pytest's tmp_path (a real, portable filesystem path) throughout --
no network, no Docker, no shelling out.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.init_deployment as init_deployment  # noqa: E402


class TestEnsureSecretFileWithHpSeedGenerator:
    def test_generates_a_64_char_hex_seed(self, tmp_path):
        path = tmp_path / "hp_seed.txt"
        status, changed = init_deployment.ensure_secret_file(path, init_deployment._generate_hp_seed)
        assert changed is True
        assert status == "generated"
        value = path.read_text(encoding="utf-8")
        assert len(value) == 64
        int(value, 16)  # raises ValueError if not valid hex

    def test_creates_parent_directory(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "hp_seed.txt"
        init_deployment.ensure_secret_file(path, init_deployment._generate_hp_seed)
        assert path.exists()

    def test_second_call_does_not_change_an_existing_seed(self, tmp_path):
        path = tmp_path / "hp_seed.txt"
        init_deployment.ensure_secret_file(path, init_deployment._generate_hp_seed)
        first_value = path.read_text(encoding="utf-8")

        status, changed = init_deployment.ensure_secret_file(path, init_deployment._generate_hp_seed)
        assert changed is False
        assert "already exists" in status
        assert path.read_text(encoding="utf-8") == first_value

    def test_force_does_regenerate(self, tmp_path):
        path = tmp_path / "hp_seed.txt"
        init_deployment.ensure_secret_file(path, init_deployment._generate_hp_seed)
        first_value = path.read_text(encoding="utf-8")

        status, changed = init_deployment.ensure_secret_file(path, init_deployment._generate_hp_seed, force=True)
        assert changed is True
        assert "regenerated" in status
        assert path.read_text(encoding="utf-8") != first_value

    def test_each_generated_seed_is_unique(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        init_deployment.ensure_secret_file(a, init_deployment._generate_hp_seed)
        init_deployment.ensure_secret_file(b, init_deployment._generate_hp_seed)
        assert a.read_text() != b.read_text()


class TestEnsureSecretFileWithBackupKeyGenerator:
    def test_generates_a_valid_fernet_key(self, tmp_path):
        path = tmp_path / "backup_encryption_key.txt"
        status, changed = init_deployment.ensure_secret_file(path, init_deployment._generate_backup_encryption_key)
        assert changed is True
        value = path.read_text(encoding="utf-8")
        Fernet(value.encode("ascii"))  # raises if not a valid Fernet key

    def test_second_call_does_not_change_an_existing_key(self, tmp_path):
        path = tmp_path / "backup_encryption_key.txt"
        init_deployment.ensure_secret_file(path, init_deployment._generate_backup_encryption_key)
        first_value = path.read_text(encoding="utf-8")

        init_deployment.ensure_secret_file(path, init_deployment._generate_backup_encryption_key)
        assert path.read_text(encoding="utf-8") == first_value

    def test_each_generated_key_is_unique(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        init_deployment.ensure_secret_file(a, init_deployment._generate_backup_encryption_key)
        init_deployment.ensure_secret_file(b, init_deployment._generate_backup_encryption_key)
        assert a.read_text() != b.read_text()


class TestManifest:
    def test_first_call_creates_a_new_manifest_with_an_id(self, tmp_path):
        path = tmp_path / "deployment-manifest.json"
        manifest = init_deployment.update_manifest(path, public_host="api.example.com", admin_host="")
        assert manifest["hp_public_host"] == "api.example.com"
        assert "deployment_id" in manifest
        assert "created_at" in manifest
        assert "hp_admin_host" not in manifest  # never set, never written as empty

    def test_deployment_id_and_created_at_survive_a_second_call(self, tmp_path):
        path = tmp_path / "deployment-manifest.json"
        first = init_deployment.update_manifest(path, public_host="api.example.com", admin_host="admin.example.com")
        second = init_deployment.update_manifest(path, public_host="new.example.com", admin_host="")
        assert second["deployment_id"] == first["deployment_id"]
        assert second["created_at"] == first["created_at"]

    def test_unset_field_on_a_later_call_does_not_erase_a_previously_set_one(self, tmp_path):
        """Re-running without --admin-host (e.g. a plain post-upgrade re-run)
        must not wipe out the admin host recorded on an earlier run."""
        path = tmp_path / "deployment-manifest.json"
        init_deployment.update_manifest(path, public_host="api.example.com", admin_host="admin.example.com")
        second = init_deployment.update_manifest(path, public_host="api.example.com", admin_host="")
        assert second["hp_admin_host"] == "admin.example.com"

    def test_host_fields_are_updated_when_given(self, tmp_path):
        path = tmp_path / "deployment-manifest.json"
        init_deployment.update_manifest(path, public_host="old.example.com", admin_host="admin.example.com")
        second = init_deployment.update_manifest(path, public_host="new.example.com", admin_host="")
        assert second["hp_public_host"] == "new.example.com"

    def test_updated_at_changes_between_calls(self, tmp_path):
        path = tmp_path / "deployment-manifest.json"
        first = init_deployment.update_manifest(path, public_host="api.example.com", admin_host="")
        import time

        time.sleep(1.1)
        second = init_deployment.update_manifest(path, public_host="api.example.com", admin_host="")
        assert second["updated_at"] != first["updated_at"]

    def test_manifest_is_valid_json_on_disk(self, tmp_path):
        path = tmp_path / "deployment-manifest.json"
        init_deployment.update_manifest(path, public_host="api.example.com", admin_host="")
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert on_disk["hp_public_host"] == "api.example.com"

    def test_corrupted_manifest_is_recovered_with_a_fresh_one_not_a_crash(self, tmp_path):
        path = tmp_path / "deployment-manifest.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        manifest = init_deployment.update_manifest(path, public_host="api.example.com", admin_host="")
        assert manifest["hp_public_host"] == "api.example.com"
        assert "deployment_id" in manifest


class TestMainIntegration:
    def test_full_run_creates_both_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "init_deployment.py",
                "--secrets-dir", str(tmp_path),
                "--public-host", "api.example.com",
                "--admin-host", "admin.example.com",
            ],
        )
        assert init_deployment.main() == 0
        assert (tmp_path / "hp_seed.txt").exists()
        assert (tmp_path / "backup_encryption_key.txt").exists()
        assert (tmp_path / "deployment-manifest.json").exists()

    def test_second_run_leaves_seed_and_backup_key_untouched(self, tmp_path, monkeypatch):
        argv = ["init_deployment.py", "--secrets-dir", str(tmp_path), "--public-host", "api.example.com"]
        monkeypatch.setattr(sys, "argv", argv)
        init_deployment.main()
        first_seed = (tmp_path / "hp_seed.txt").read_text()
        first_backup_key = (tmp_path / "backup_encryption_key.txt").read_text()

        init_deployment.main()
        assert (tmp_path / "hp_seed.txt").read_text() == first_seed
        assert (tmp_path / "backup_encryption_key.txt").read_text() == first_backup_key

    def test_force_flag_regenerates_the_seed(self, tmp_path, monkeypatch):
        base_argv = ["init_deployment.py", "--secrets-dir", str(tmp_path), "--public-host", "api.example.com"]
        monkeypatch.setattr(sys, "argv", base_argv)
        init_deployment.main()
        first_seed = (tmp_path / "hp_seed.txt").read_text()
        first_backup_key = (tmp_path / "backup_encryption_key.txt").read_text()

        monkeypatch.setattr(sys, "argv", base_argv + ["--force-regenerate-seed"])
        init_deployment.main()
        assert (tmp_path / "hp_seed.txt").read_text() != first_seed
        assert (tmp_path / "backup_encryption_key.txt").read_text() == first_backup_key  # untouched

    def test_force_backup_key_flag_regenerates_only_the_backup_key(self, tmp_path, monkeypatch):
        base_argv = ["init_deployment.py", "--secrets-dir", str(tmp_path), "--public-host", "api.example.com"]
        monkeypatch.setattr(sys, "argv", base_argv)
        init_deployment.main()
        first_seed = (tmp_path / "hp_seed.txt").read_text()
        first_backup_key = (tmp_path / "backup_encryption_key.txt").read_text()

        monkeypatch.setattr(sys, "argv", base_argv + ["--force-regenerate-backup-key"])
        init_deployment.main()
        assert (tmp_path / "hp_seed.txt").read_text() == first_seed  # untouched
        assert (tmp_path / "backup_encryption_key.txt").read_text() != first_backup_key
