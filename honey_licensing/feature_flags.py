from __future__ import annotations

import threading
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
    API_MUTATION = "api_mutation"
    ANALYTICS = "analytics"
    WEBHOOKS = "webhooks"


_CORE_FEATURES: Set[str] = set()
_PRO_FEATURES: Set[str] = {
    Feature.CASES.value,
    Feature.CAMPAIGNS.value,
    Feature.REPLAY.value,
    Feature.ADVANCED_SCORING.value,
    Feature.FILE_PIPELINE.value,
    Feature.API_MUTATION.value,
    Feature.ANALYTICS.value,
    Feature.WEBHOOKS.value,
}

_PROVIDER_LOCK = threading.Lock()
_PRO_ENABLED_PROVIDER: Optional[Callable[[], bool]] = None
# True once a real provider has been installed. Prevents replacing the provider
# with an arbitrary callable (e.g. lambda: True) after startup.
_PROVIDER_INITIALIZED: bool = False


def set_pro_enabled_provider(fn: Optional[Callable[[], bool]]) -> None:
    global _PRO_ENABLED_PROVIDER, _PROVIDER_INITIALIZED
    with _PROVIDER_LOCK:
        if fn is None:
            # Clearing is always allowed (called by shutdown handlers).
            _PRO_ENABLED_PROVIDER = None
            _PROVIDER_INITIALIZED = False
            return
        if _PROVIDER_INITIALIZED:
            # Already set — silently ignore replacement attempts.
            # An attacker calling set_pro_enabled_provider(lambda: True) after
            # startup will find the legitimate provider already in place.
            return
        _PRO_ENABLED_PROVIDER = fn
        _PROVIDER_INITIALIZED = True


def is_pro_enabled() -> bool:
    with _PROVIDER_LOCK:
        fn = _PRO_ENABLED_PROVIDER
    if fn is not None:
        try:
            return bool(fn())
        except Exception:
            return False
    return False


def get_license_tier() -> LicenseTier:
    with _PROVIDER_LOCK:
        initialized = _PROVIDER_INITIALIZED
    if initialized:
        return LicenseTier.PRO if is_pro_enabled() else LicenseTier.CORE
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
