"""NOC-027: scripts/dr_drill.py's non-Docker-dependent pieces.

The drill itself (backup -> destroy -> restore -> verify against a real
throwaway compose project) was run manually against real Docker as this
Issue's actual verification evidence -- see the PR body for the measured
RTO/RPO. That full orchestration isn't part of the automated suite (it
needs a pre-built app image, which CI doesn't build), but the one piece
of pure logic it contains -- generating the throwaway, non-real env file
-- is tested here.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.dr_drill as dr_drill  # noqa: E402


def _parse_env(content: str) -> dict:
    result = {}
    for line in content.strip().splitlines():
        key, _, value = line.partition("=")
        result[key] = value
    return result


class TestDefaultEnvFileContent:
    def test_contains_every_required_key(self):
        env = _parse_env(dr_drill.default_env_file_content("ghcr.io/example/app:v1.2.3"))
        for key in (
            "APP_ENV", "HP_PUBLIC_HOST", "HP_ADMIN_HOST", "ACME_EMAIL", "HP_PANEL_TOKEN",
            "CLOUDFLARE_TUNNEL_TOKEN", "APP_VERSION", "HP_IMAGE", "HP_SEED", "HP_BACKUP_ENCRYPTION_KEY",
        ):
            assert key in env, f"missing {key}"

    def test_splits_a_tagged_image_into_hp_image_and_app_version(self):
        env = _parse_env(dr_drill.default_env_file_content("ghcr.io/example/app:v1.2.3"))
        assert env["HP_IMAGE"] == "ghcr.io/example/app"
        assert env["APP_VERSION"] == "v1.2.3"

    def test_untagged_image_falls_back_to_defaults(self):
        env = _parse_env(dr_drill.default_env_file_content(""))
        assert env["HP_IMAGE"] == "ghcr.io/0x-unkwn0wn/noctisapi-pro"
        assert env["APP_VERSION"] == "latest"

    def test_hp_seed_is_a_64_char_hex_string(self):
        env = _parse_env(dr_drill.default_env_file_content("some/image:tag"))
        assert len(env["HP_SEED"]) == 64
        int(env["HP_SEED"], 16)

    def test_backup_encryption_key_is_a_valid_fernet_key(self):
        from cryptography.fernet import Fernet

        env = _parse_env(dr_drill.default_env_file_content("some/image:tag"))
        Fernet(env["HP_BACKUP_ENCRYPTION_KEY"].encode("ascii"))  # raises if invalid

    def test_two_calls_generate_different_secrets(self):
        env_a = _parse_env(dr_drill.default_env_file_content("img:tag"))
        env_b = _parse_env(dr_drill.default_env_file_content("img:tag"))
        assert env_a["HP_SEED"] != env_b["HP_SEED"]
        assert env_a["HP_BACKUP_ENCRYPTION_KEY"] != env_b["HP_BACKUP_ENCRYPTION_KEY"]

    def test_never_touches_real_hosts(self):
        """Every drill-generated value is clearly a placeholder -- this
        must never resolve to, or be mistaken for, a real deployment's
        config."""
        content = dr_drill.default_env_file_content("img:tag")
        assert "dr-drill.invalid" in content
        assert ".invalid" in content
