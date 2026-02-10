"""
Compatibility shim.

The licensing runtime client is implemented in `honey_licensing.client` so it can be
reused by other apps. This module re-exports the public API for existing imports.
"""

from honey_licensing.client import (  # noqa: F401
    LicenseDecision,
    LicensingClientError,
    LicensingManager,
    LicensingStartupDenied,
    LicensingState,
    compute_client_identity,
    compute_instance_fingerprint_sha256_hex,
    get_default_manager,
    get_or_create_uuid_file,
    load_pinned_public_key_pem,
    post_json,
    verify_jws_rs256_compact,
)

__all__ = [
    "LicenseDecision",
    "LicensingClientError",
    "LicensingManager",
    "LicensingStartupDenied",
    "LicensingState",
    "compute_client_identity",
    "compute_instance_fingerprint_sha256_hex",
    "get_default_manager",
    "get_or_create_uuid_file",
    "load_pinned_public_key_pem",
    "post_json",
    "verify_jws_rs256_compact",
]

