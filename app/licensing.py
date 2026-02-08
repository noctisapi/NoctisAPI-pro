from __future__ import annotations

import os
from enum import Enum
from typing import Set


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


def get_license_tier() -> LicenseTier:
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
    }
