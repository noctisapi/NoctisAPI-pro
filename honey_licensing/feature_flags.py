from __future__ import annotations

import os
from enum import Enum
from typing import Callable, Optional, Set


class LicenseTier(str, Enum):
    CORE = "core"
    PRO = "pro"


class Feature(str, Enum):
    CASES = "cases"
    CAMPAIGNS = "campaigns"
    REPLAY = "replay"
    ADVANCED_SCORING = "advanced_scoring"
    FILE_PIPELINE = "file_pipeline"


_CORE_FEATURES: Set[str] = set()
_PRO_FEATURES: Set[str] = {
    Feature.CASES.value,
    Feature.CAMPAIGNS.value,
    Feature.REPLAY.value,
    Feature.ADVANCED_SCORING.value,
    Feature.FILE_PIPELINE.value,
}

_PRO_ENABLED_PROVIDER: Optional[Callable[[], bool]] = None


def set_pro_enabled_provider(fn: Optional[Callable[[], bool]]) -> None:
    global _PRO_ENABLED_PROVIDER
    _PRO_ENABLED_PROVIDER = fn


def is_pro_enabled() -> bool:
    if _PRO_ENABLED_PROVIDER is not None:
        try:
            return bool(_PRO_ENABLED_PROVIDER())
        except Exception:
            return False
    return False


def get_license_tier() -> LicenseTier:
    # Preferred: runtime licensing provider (LICENSE_KEY -> /activate, /validate).
    if _PRO_ENABLED_PROVIDER is not None:
        return LicenseTier.PRO if is_pro_enabled() else LicenseTier.CORE

    # Backward-compatible fallback (manual override).
    raw = (os.getenv("HP_LICENSE_TIER") or "core").strip().lower()
    if raw == LicenseTier.PRO.value:
        return LicenseTier.PRO
    return LicenseTier.CORE


def enabled_features() -> Set[str]:
    tier = get_license_tier()
    if tier == LicenseTier.PRO:
        return set(_PRO_FEATURES)
    return set(_CORE_FEATURES)


def has_feature(feature: str | Feature) -> bool:
    name = feature.value if isinstance(feature, Feature) else str(feature)
    return name in enabled_features()


def feature_flags() -> dict:
    return {
        "license_tier": get_license_tier().value,
        "license_features": sorted(enabled_features()),
        "pro_enabled": bool(get_license_tier() == LicenseTier.PRO),
    }
