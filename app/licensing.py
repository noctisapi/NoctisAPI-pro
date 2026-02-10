"""
Compatibility shim.

Feature gating helpers live in `honey_licensing.feature_flags` so the same licensing
approach can be reused by other apps. This module re-exports the public API for
existing imports within this app.
"""

from honey_licensing.feature_flags import (  # noqa: F401
    Feature,
    LicenseTier,
    enabled_features,
    feature_flags,
    get_license_tier,
    has_feature,
    is_pro_enabled,
    set_pro_enabled_provider,
)

__all__ = [
    "Feature",
    "LicenseTier",
    "enabled_features",
    "feature_flags",
    "get_license_tier",
    "has_feature",
    "is_pro_enabled",
    "set_pro_enabled_provider",
]

