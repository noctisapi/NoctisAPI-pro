import ipaddress
import json
import logging
import os
import threading
from typing import Any, Optional

_logger = logging.getLogger(__name__)

_reader_lock = threading.Lock()
_reader = None
_reader_path = ""
_warned_keys: set[str] = set()


def _warn_once(key: str, message: str, *, logger: Optional[logging.Logger] = None) -> None:
    if key in _warned_keys:
        return
    _warned_keys.add(key)
    (logger or _logger).warning(message)


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
        return {"country_iso2": "", "country_name": "", "flag": ""}
    iso2 = str(geo.get("country_iso2") or geo.get("geo_iso2") or "").strip().upper()
    name = str(geo.get("country_name") or geo.get("geo_name") or "").strip()
    flag = str(geo.get("flag") or geo.get("geo_flag") or "").strip()
    if not flag and iso2:
        flag = flag_emoji_from_iso2(iso2)
    return {
        "country_iso2": iso2,
        "country_name": name,
        "flag": flag,
    }


def parse_geo_from_extra_json(extra_json: Any) -> dict[str, str]:
    try:
        payload = extra_json
        if isinstance(extra_json, str):
            payload = json.loads(extra_json or "{}")
        if isinstance(payload, dict):
            geo = payload.get("geo", payload)
            normalized = normalize_geo_dict(geo)
            return {
                "geo_flag": normalized["flag"],
                "geo_iso2": normalized["country_iso2"],
                "geo_name": normalized["country_name"],
            }
    except Exception:
        pass
    return {"geo_flag": "", "geo_iso2": "", "geo_name": ""}


def _load_reader(mmdb_path: str, *, logger: Optional[logging.Logger] = None):
    global _reader, _reader_path
    if not mmdb_path:
        _warn_once("geoip-missing-path", "GeoIP disabled: HP_GEOIP_DB is empty.", logger=logger)
        return None
    if not os.path.exists(mmdb_path):
        _warn_once(
            f"geoip-missing-db:{mmdb_path}",
            f"GeoIP disabled: database not found at {mmdb_path}.",
            logger=logger,
        )
        return None
    with _reader_lock:
        if _reader is not None and _reader_path == mmdb_path:
            return _reader
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
            _reader = geoip2.database.Reader(mmdb_path)
            _reader_path = mmdb_path
            return _reader
        except Exception as exc:
            _warn_once(
                f"geoip-open-failed:{mmdb_path}",
                f"GeoIP disabled: unable to open {mmdb_path} ({exc.__class__.__name__}).",
                logger=logger,
            )
            return None


def lookup_country(ip_s: str, *, mmdb_path: str, logger: Optional[logging.Logger] = None) -> dict[str, str]:
    if not is_public_ip(ip_s):
        return {}
    reader = _load_reader(mmdb_path, logger=logger)
    if reader is None:
        return {}
    try:
        response = reader.country(ip_s)
        return normalize_geo_dict(
            {
                "country_iso2": (response.country.iso_code or "").strip().upper(),
                "country_name": (response.country.name or "").strip(),
            }
        )
    except Exception:
        return {}
