from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache
from typing import Any, Iterator, Optional

import httpx

from app.proxy_config import build_httpx_mounts
from app.tls_config import get_ssl_context

_logger = logging.getLogger(__name__)

DEFAULT_RESOLVER_URL = "https://ipwho.is/{ip}"
RESOLVER_URL_ENV_VARS = (
    "HP_ASN_RESOLVER_URL",
    "HP_GEO_RESOLVER_URL",
    "ASN_RESOLVER_URL",
    "GEO_RESOLVER_URL",
)
TIMEOUT_ENV_VARS = (
    "HP_ASN_RESOLVER_TIMEOUT_SECONDS",
    "HP_GEO_RESOLVER_TIMEOUT_SECONDS",
)
DEFAULT_TIMEOUT_SECONDS = 5.0

_warned_keys: set[str] = set()


def _warn_once(key: str, message: str, *, logger: Optional[logging.Logger] = None) -> None:
    if key in _warned_keys:
        return
    _warned_keys.add(key)
    (logger or _logger).warning(message)


def get_resolver_url(configured_url: Optional[str] = None) -> str:
    if configured_url is not None and str(configured_url).strip():
        return str(configured_url).strip()
    for env_name in RESOLVER_URL_ENV_VARS:
        raw = str(os.getenv(env_name) or "").strip()
        if raw:
            return raw
    return DEFAULT_RESOLVER_URL


def get_timeout_seconds() -> float:
    for env_name in TIMEOUT_ENV_VARS:
        raw = str(os.getenv(env_name) or "").strip()
        if not raw:
            continue
        try:
            timeout = float(raw)
        except ValueError:
            continue
        if timeout > 0:
            return timeout
    return DEFAULT_TIMEOUT_SECONDS


def is_public_ip(ip_s: str) -> bool:
    try:
        return bool(ipaddress.ip_address(ip_s).is_global)
    except Exception:
        return False


def _format_url(template: str, ip_s: str) -> str:
    if "{ip}" not in template:
        raise ValueError("resolver URL must contain the {ip} placeholder")
    return template.format(ip=ip_s)


def _iter_dicts(payload: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(payload, dict):
        return
    yield payload
    for value in payload.values():
        if isinstance(value, dict):
            yield from _iter_dicts(value)


def _extract_country_name(payload: dict[str, Any]) -> str:
    for node in _iter_dicts(payload):
        for key in ("country_name", "countryName", "geo_name"):
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        country_value = node.get("country")
        if isinstance(country_value, str) and country_value.strip():
            return country_value.strip()
    return ""


def _extract_country_iso2(payload: dict[str, Any]) -> str:
    for node in _iter_dicts(payload):
        for key in ("country_iso2", "country_code", "countryCode", "geo_iso2", "iso_code", "isoCode"):
            value = node.get(key)
            if isinstance(value, str):
                iso2 = value.strip().upper()
                if len(iso2) == 2 and iso2.isalpha():
                    return iso2
        country_value = node.get("country")
        if isinstance(country_value, dict):
            for key in ("iso2", "iso_code", "code", "country_code"):
                value = country_value.get(key)
                if isinstance(value, str):
                    iso2 = value.strip().upper()
                    if len(iso2) == 2 and iso2.isalpha():
                        return iso2
    return ""


@lru_cache(maxsize=4096)
def _lookup_country_cached(ip_s: str, resolver_url: str) -> tuple[str, str]:
    request_url = _format_url(resolver_url, ip_s)
    ssl_ctx = get_ssl_context()
    mounts = build_httpx_mounts(ssl_ctx)
    with httpx.Client(
        verify=ssl_ctx,
        mounts=mounts,
        timeout=get_timeout_seconds(),
        headers={"Accept": "application/json"},
    ) as client:
        response = client.get(request_url)
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        return ("", "")
    return (_extract_country_iso2(payload), _extract_country_name(payload))


def warmup(*, configured_url: Optional[str] = None, logger: Optional[logging.Logger] = None) -> bool:
    resolver_url = get_resolver_url(configured_url)
    try:
        _format_url(resolver_url, "127.0.0.1")
    except ValueError as exc:
        _warn_once("asn-resolver-bad-template", f"Geo enrichment disabled: {exc}.", logger=logger)
        return False
    return True


def close() -> None:
    _lookup_country_cached.cache_clear()


def get_country_code(
    ip_s: str,
    *,
    configured_url: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> Optional[str]:
    if not is_public_ip(ip_s):
        return None
    resolver_url = get_resolver_url(configured_url)
    if not warmup(configured_url=resolver_url, logger=logger):
        return None
    try:
        iso2, _ = _lookup_country_cached(ip_s, resolver_url)
    except Exception as exc:
        _warn_once(
            f"asn-resolver-failed:{type(exc).__name__}",
            f"Geo enrichment failed via ASN resolver ({exc.__class__.__name__}).",
            logger=logger,
        )
        return None
    return iso2 or None


def lookup_country(
    ip_s: str,
    *,
    configured_url: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> dict[str, str]:
    iso2 = get_country_code(ip_s, configured_url=configured_url, logger=logger)
    if not iso2:
        return {}
    resolver_url = get_resolver_url(configured_url)
    try:
        cached_iso2, cached_name = _lookup_country_cached(ip_s, resolver_url)
    except Exception:
        return {}
    return {
        "country_iso2": cached_iso2,
        "country_code": cached_iso2,
        "country_name": cached_name,
    }
