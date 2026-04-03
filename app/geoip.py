import ipaddress
import json
import logging
import os
import threading
from functools import lru_cache
from typing import Any, Optional

_logger = logging.getLogger(__name__)

DEFAULT_GEOIP_DB_PATH = "/data/GeoLite2-Country.mmdb"
GEOIP_DB_ENV_VARS = ("GEOIP_DB_PATH", "HP_GEOIP_DB")

_reader_lock = threading.Lock()
_reader = None
_reader_path = ""
_warned_keys: set[str] = set()


def _warn_once(key: str, message: str, *, logger: Optional[logging.Logger] = None) -> None:
    if key in _warned_keys:
        return
    _warned_keys.add(key)
    (logger or _logger).warning(message)


def get_geoip_db_path(configured_path: Optional[str] = None) -> str:
    if configured_path is not None and str(configured_path).strip():
        return str(configured_path).strip()
    for env_name in GEOIP_DB_ENV_VARS:
        raw = str(os.getenv(env_name) or "").strip()
        if raw:
            return raw
    return DEFAULT_GEOIP_DB_PATH


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


def _load_reader(mmdb_path: Optional[str] = None, *, logger: Optional[logging.Logger] = None):
    global _reader, _reader_path
    resolved_path = get_geoip_db_path(mmdb_path)
    if not resolved_path:
        _warn_once(
            "geoip-missing-path",
            "GeoIP disabled: GEOIP_DB_PATH/HP_GEOIP_DB is empty.",
            logger=logger,
        )
        return None
    if not os.path.exists(resolved_path):
        _warn_once(
            f"geoip-missing-db:{resolved_path}",
            (
                f"GeoIP disabled: database not found at {resolved_path}. "
                "Download GeoLite2-Country.mmdb from MaxMind and set GEOIP_DB_PATH."
            ),
            logger=logger,
        )
        return None
    with _reader_lock:
        if _reader is not None and _reader_path == resolved_path:
            return _reader
        if _reader is not None:
            try:
                _reader.close()
            except Exception:
                pass
            _reader = None
            _reader_path = ""
        try:
            import geoip2.database  # type: ignore
        except Exception as exc:
            _warn_once(
                "geoip-missing-lib",
                f"GeoIP disabled: unable to import geoip2 ({exc.__class__.__name__}).",
                logger=logger,
            )
            return None
        try:
            _reader = geoip2.database.Reader(resolved_path)
            _reader_path = resolved_path
            return _reader
        except Exception as exc:
            _warn_once(
                f"geoip-open-failed:{resolved_path}",
                f"GeoIP disabled: unable to open {resolved_path} ({exc.__class__.__name__}).",
                logger=logger,
            )
            return None


def warmup_reader(mmdb_path: Optional[str] = None, *, logger: Optional[logging.Logger] = None) -> bool:
    return _load_reader(mmdb_path, logger=logger) is not None


def close_reader() -> None:
    global _reader, _reader_path
    with _reader_lock:
        if _reader is not None:
            try:
                _reader.close()
            except Exception:
                pass
        _reader = None
        _reader_path = ""
    _lookup_country_cached.cache_clear()


@lru_cache(maxsize=4096)
def _lookup_country_cached(ip_s: str, mmdb_path: str) -> tuple[str, str]:
    reader = _load_reader(mmdb_path)
    if reader is None:
        return ("", "")
    try:
        response = reader.country(ip_s)
        iso2 = str(response.country.iso_code or "").strip().upper()
        name = str(response.country.name or "").strip()
        return (iso2, name)
    except Exception:
        return ("", "")


def get_country_code(
    ip: str,
    *,
    mmdb_path: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> Optional[str]:
    if not is_public_ip(ip):
        return None
    resolved_path = get_geoip_db_path(mmdb_path)
    if not warmup_reader(resolved_path, logger=logger):
        return None
    iso2, _name = _lookup_country_cached(ip, resolved_path)
    return iso2 or None


def lookup_country(
    ip_s: str,
    *,
    mmdb_path: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> dict[str, str]:
    iso2 = get_country_code(ip_s, mmdb_path=mmdb_path, logger=logger)
    if not iso2:
        return {}
    resolved_path = get_geoip_db_path(mmdb_path)
    cached_iso2, cached_name = _lookup_country_cached(ip_s, resolved_path)
    normalized = normalize_geo_dict(
        {
            "country_iso2": cached_iso2,
            "country_name": cached_name,
        }
    )
    return dict(normalized)
