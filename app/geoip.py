from __future__ import annotations

import ipaddress
import json
from typing import Any, Optional

from app.geo import asn_resolver

DEFAULT_GEOIP_DB_PATH = asn_resolver.DEFAULT_RESOLVER_URL
GEOIP_DB_ENV_VARS = asn_resolver.RESOLVER_URL_ENV_VARS


def get_geoip_db_path(configured_path: Optional[str] = None) -> str:
    """Compatibility wrapper for the legacy GeoIP config accessor."""
    return asn_resolver.get_resolver_url(configured_path)


def is_public_ip(ip_s: str) -> bool:
    try:
        return bool(ipaddress.ip_address(ip_s).is_global)
    except Exception:
        return False


def flag_emoji_from_iso2(iso2: str) -> str:
    iso2 = (iso2 or "").strip().upper()
    if len(iso2) != 2 or not iso2.isalpha():
        return ""
    base = 0x1F1E6
    return chr(base + (ord(iso2[0]) - ord("A"))) + chr(base + (ord(iso2[1]) - ord("A")))


def normalize_geo_dict(geo: Any) -> dict[str, str]:
    if not isinstance(geo, dict):
        return {"country_iso2": "", "country_code": "", "country_name": "", "flag": ""}
    iso2 = str(
        geo.get("country_iso2")
        or geo.get("country_code")
        or geo.get("geo_iso2")
        or ""
    ).strip().upper()
    name = str(geo.get("country_name") or geo.get("geo_name") or "").strip()
    flag = str(geo.get("flag") or geo.get("geo_flag") or "").strip()
    if not flag and iso2:
        flag = flag_emoji_from_iso2(iso2)
    return {
        "country_iso2": iso2,
        "country_code": iso2,
        "country_name": name,
        "flag": flag,
    }


def parse_geo_from_extra_json(extra_json: Any) -> dict[str, str]:
    try:
        payload = extra_json
        if isinstance(extra_json, str):
            payload = json.loads(extra_json or "{}")
        if isinstance(payload, dict):
            geo = payload.get("geo") or payload
            normalized = normalize_geo_dict(geo)
            return {
                "geo_flag": normalized["flag"],
                "geo_iso2": normalized["country_iso2"],
                "geo_country_code": normalized["country_code"],
                "geo_name": normalized["country_name"],
            }
    except Exception:
        pass
    return {"geo_flag": "", "geo_iso2": "", "geo_country_code": "", "geo_name": ""}


def warmup_reader(mmdb_path: Optional[str] = None, *, logger=None) -> bool:
    return asn_resolver.warmup(configured_url=mmdb_path, logger=logger)


def close_reader() -> None:
    asn_resolver.close()


def get_country_code(
    ip: str,
    *,
    mmdb_path: Optional[str] = None,
    logger=None,
) -> Optional[str]:
    return asn_resolver.get_country_code(ip, configured_url=mmdb_path, logger=logger)


def lookup_country(
    ip_s: str,
    *,
    mmdb_path: Optional[str] = None,
    logger=None,
) -> dict[str, str]:
    geo = asn_resolver.lookup_country(ip_s, configured_url=mmdb_path, logger=logger)
    return normalize_geo_dict(geo) if geo else {}
