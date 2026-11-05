"""NOC-026: scripts/backup_tool.py -- encrypt/decrypt backup artifacts
with a dedicated Fernet key (never the HP_SEED-derived one app.log_export_stream
uses for the system_secrets table)."""
from __future__ import annotations

import sys
from pathlib import Path

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.backup_tool as backup_tool  # noqa: E402


def _key() -> bytes:
    return Fernet.generate_key()


class TestLoadKey:
    def test_missing_key_exits_with_error(self, monkeypatch):
        monkeypatch.delenv("HP_BACKUP_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("HP_BACKUP_ENCRYPTION_KEY_FILE", raising=False)
        try:
            backup_tool.load_key()
            assert False, "expected SystemExit"
        except SystemExit as exc:
            assert exc.code == 2

    def test_key_from_plain_env_var(self, monkeypatch):
        key = _key()
        monkeypatch.delenv("HP_BACKUP_ENCRYPTION_KEY_FILE", raising=False)
        monkeypatch.setenv("HP_BACKUP_ENCRYPTION_KEY", key.decode())
        assert backup_tool.load_key() == key

    def test_key_from_file_takes_priority(self, monkeypatch, tmp_path):
        key = _key()
        key_file = tmp_path / "key.txt"
        key_file.write_text(key.decode())
        monkeypatch.setenv("HP_BACKUP_ENCRYPTION_KEY_FILE", str(key_file))
        monkeypatch.setenv("HP_BACKUP_ENCRYPTION_KEY", "should-be-ignored")
        assert backup_tool.load_key() == key


class TestEncryptDecryptRoundTrip:
    def test_round_trip_recovers_original_bytes(self, tmp_path):
        key = _key()
        src = tmp_path / "plain.bin"
        src.write_bytes(b"not valid utf-8: \xff\xfe\x00binary sqlite-like content")
        enc = tmp_path / "plain.bin.enc"
        dec = tmp_path / "plain.bin.dec"

        backup_tool.encrypt_file(src, enc, key)
        assert enc.read_bytes() != src.read_bytes()  # actually encrypted, not a no-op

        backup_tool.decrypt_file(enc, dec, key)
        assert dec.read_bytes() == src.read_bytes()

    def test_wrong_key_fails_to_decrypt(self, tmp_path):
        src = tmp_path / "plain.bin"
        src.write_bytes(b"some content")
        enc = tmp_path / "plain.bin.enc"
        dec = tmp_path / "plain.bin.dec"

        backup_tool.encrypt_file(src, enc, _key())
        try:
            backup_tool.decrypt_file(enc, dec, _key())
            assert False, "expected SystemExit on wrong key"
        except SystemExit as exc:
            assert exc.code == 1


class TestMainIntegration:
    def test_encrypt_then_decrypt_cli_round_trip(self, tmp_path, monkeypatch):
        key = _key()
        monkeypatch.setenv("HP_BACKUP_ENCRYPTION_KEY", key.decode())
        monkeypatch.delenv("HP_BACKUP_ENCRYPTION_KEY_FILE", raising=False)

        src = tmp_path / "db.bin"
        src.write_bytes(b"sqlite-ish bytes")
        enc = tmp_path / "db.bin.enc"
        dec = tmp_path / "db.bin.dec"

        monkeypatch.setattr(sys, "argv", ["backup_tool.py", "encrypt", str(src), str(enc)])
        assert backup_tool.main() == 0

        monkeypatch.setattr(sys, "argv", ["backup_tool.py", "decrypt", str(enc), str(dec)])
        assert backup_tool.main() == 0
        assert dec.read_bytes() == src.read_bytes()

    def test_missing_source_file_exits_2(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HP_BACKUP_ENCRYPTION_KEY", _key().decode())
        monkeypatch.setattr(
            sys, "argv",
            ["backup_tool.py", "encrypt", str(tmp_path / "nope.bin"), str(tmp_path / "out.enc")],
        )
        assert backup_tool.main() == 2
