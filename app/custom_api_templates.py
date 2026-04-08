"""User-defined Modular API templates.

Templates are declarative data stored in SQLite. They are intentionally not
code: no Python, no JS, no arbitrary templating engine.
"""
from __future__ import annotations

import copy
import json
import logging
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from app.catalog.definitions import BaseTemplateDefinition, EndpointDefinition, EndpointGroupDefinition
from app.catalog.registry import CatalogRegistry, CatalogValidationError
from app.catalog.types import HttpMethod, OperationType, ResourceType, SensitivityLevel, SurfaceType

logger = logging.getLogger(__name__)

TABLE_NAME = "api_custom_templates"
CUSTOM_PREFIX = "custom_"
DEFAULT_RESPONSE_PROFILE_ID = "standard_medium"
MAX_TEMPLATES = 25
MAX_ENDPOINTS_PER_TEMPLATE = 100
MAX_BODY_BYTES = 32768
MAX_DESCRIPTION_CHARS = 500
MAX_HEADERS = 20

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_PATH_PARAM_RE = re.compile(r"\{([^}/]+)\}")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_RESERVED_PREFIXES = (
    "/dashboard",
    "/static",
)
_RESERVED_EXACT = {
    "/docs",
    "/redoc",
    "/ready",
    "/health",
    "/openapi.json",
}
_ALLOWED_CONTENT_TYPES = {
    "application/json",
    "text/plain",
}
_AUTH_MODES = {
    "none",
    "bearer_required",
    "api_key_required",
    "token_issuer",
    "api_key_issuer",
}
_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "content-length",
    "transfer-encoding",
    "connection",
}


class CustomTemplateError(ValueError):
    pass


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
          template_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          payload_json TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()


def _slugify_id(value: Any, *, prefix: str = "") -> str:
    raw = str(value or "").strip().lower()
    raw = re.sub(r"[^a-z0-9_]+", "_", raw)
    raw = re.sub(r"_+", "_", raw).strip("_")
    if not raw or not raw[0].isalpha():
        raw = f"{prefix or 'item'}_{raw}".strip("_")
    if prefix and not raw.startswith(prefix):
        raw = f"{prefix}{raw}"
    return raw[:64]


def _require_id(value: Any, *, field: str, prefix: str = "") -> str:
    item_id = _slugify_id(value, prefix=prefix)
    if not _ID_RE.match(item_id):
        raise CustomTemplateError(f"{field}_invalid")
    return item_id


def _normalize_method(value: Any) -> str:
    raw = str(value or "GET").strip().upper()
    if raw not in {item.value for item in HttpMethod}:
        raise CustomTemplateError("method_invalid")
    return raw


def _normalize_path(value: Any) -> str:
    path = str(value or "").strip()
    if not path:
        raise CustomTemplateError("path_required")
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 240:
        raise CustomTemplateError("path_too_long")
    if ".." in path or "//" in path:
        raise CustomTemplateError("path_invalid")
    lowered = path.lower().rstrip("/") or "/"
    if lowered in _RESERVED_EXACT or any(lowered.startswith(prefix) for prefix in _RESERVED_PREFIXES):
        raise CustomTemplateError("path_reserved")
    return path.rstrip("/") or "/"


def _normalize_content_type(value: Any) -> str:
    raw = str(value or "application/json").strip().lower()
    if raw not in _ALLOWED_CONTENT_TYPES:
        raise CustomTemplateError("content_type_invalid")
    return raw


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except Exception:
        return MAX_BODY_BYTES + 1


def _normalize_headers(raw: Any) -> dict[str, str]:
    if raw in (None, ""):
        return {}
    if not isinstance(raw, dict):
        raise CustomTemplateError("headers_invalid")
    if len(raw) > MAX_HEADERS:
        raise CustomTemplateError("headers_too_many")
    headers: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key or "").strip()
        if not name or not re.match(r"^[A-Za-z0-9-]{1,64}$", name):
            raise CustomTemplateError("header_name_invalid")
        if name.lower() in _SENSITIVE_HEADERS:
            raise CustomTemplateError(f"header_reserved:{name}")
        rendered = str(value if value is not None else "").strip()
        if len(rendered) > 512:
            raise CustomTemplateError("header_value_too_long")
        headers[name] = rendered
    return headers


def _normalize_auth(raw: Any) -> dict[str, Any]:
    if raw in (None, ""):
        raw = {}
    if isinstance(raw, str):
        raw = {"mode": raw}
    if not isinstance(raw, dict):
        raise CustomTemplateError("auth_invalid")

    mode = str(raw.get("mode") or "none").strip().lower()
    if mode not in _AUTH_MODES:
        raise CustomTemplateError("auth_mode_invalid")

    try:
        fail_status = int(raw.get("fail_status") or 401)
    except Exception:
        raise CustomTemplateError("auth_fail_status_invalid")
    if not (100 <= fail_status <= 599):
        raise CustomTemplateError("auth_fail_status_invalid")

    fail_content_type = _normalize_content_type(raw.get("fail_content_type") or "application/json")
    fail_body = raw.get("fail_body", {"detail": "Unauthorized"})
    if fail_content_type == "application/json":
        if not isinstance(fail_body, (dict, list, str, int, float, bool)) and fail_body is not None:
            raise CustomTemplateError("auth_fail_body_invalid")
        if _json_size(fail_body) > MAX_BODY_BYTES:
            raise CustomTemplateError("auth_fail_body_too_large")
    else:
        fail_body = str(fail_body if fail_body is not None else "")
        if len(fail_body.encode("utf-8")) > MAX_BODY_BYTES:
            raise CustomTemplateError("auth_fail_body_too_large")

    fail_headers = _normalize_headers(raw.get("fail_headers"))
    if mode == "bearer_required" and fail_status == 401:
        fail_headers.setdefault("WWW-Authenticate", "Bearer")

    return {
        "mode": mode,
        "fail_status": fail_status,
        "fail_content_type": fail_content_type,
        "fail_headers": fail_headers,
        "fail_body": fail_body,
    }


def _operation_for(method: str, path: str) -> OperationType:
    if method == "GET":
        return OperationType.OBJECT_READ if _PATH_PARAM_RE.search(path) else OperationType.COLLECTION_LIST
    if method == "POST":
        return OperationType.OBJECT_CREATE
    if method in {"PUT", "PATCH"}:
        return OperationType.OBJECT_UPDATE
    if method == "DELETE":
        return OperationType.OBJECT_DELETE
    return OperationType.OBJECT_READ


def normalize_template_payload(raw: dict[str, Any], *, existing_template_id: Optional[str] = None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CustomTemplateError("payload_invalid")

    template_id = _require_id(
        existing_template_id or raw.get("id") or raw.get("template_id") or raw.get("name"),
        field="template_id",
        prefix=CUSTOM_PREFIX,
    )
    name = str(raw.get("name") or template_id.removeprefix(CUSTOM_PREFIX).replace("_", " ").title()).strip()
    if not name:
        raise CustomTemplateError("name_required")
    if len(name) > 100:
        raise CustomTemplateError("name_too_long")
    description = str(raw.get("description") or "").strip()[:MAX_DESCRIPTION_CHARS]
    default_response_profile_id = str(raw.get("default_response_profile_id") or DEFAULT_RESPONSE_PROFILE_ID).strip()

    raw_endpoints = raw.get("endpoints")
    if not isinstance(raw_endpoints, list):
        raise CustomTemplateError("endpoints_invalid")
    if not raw_endpoints:
        raise CustomTemplateError("endpoints_required")
    if len(raw_endpoints) > MAX_ENDPOINTS_PER_TEMPLATE:
        raise CustomTemplateError("endpoints_too_many")

    endpoints: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_routes: set[tuple[str, str]] = set()

    for index, item in enumerate(raw_endpoints, start=1):
        if not isinstance(item, dict):
            raise CustomTemplateError(f"endpoint_invalid:{index}")
        method = _normalize_method(item.get("method"))
        path = _normalize_path(item.get("path") or item.get("path_pattern"))
        endpoint_id = _require_id(
            item.get("id") or item.get("endpoint_id") or f"{method.lower()}_{path.strip('/').replace('/', '_')}",
            field=f"endpoint_id:{index}",
        )
        endpoint_id = f"{template_id}_{endpoint_id.removeprefix(template_id + '_')}"
        if endpoint_id in seen_ids:
            raise CustomTemplateError(f"endpoint_id_duplicate:{endpoint_id}")
        route_key = (method, path)
        if route_key in seen_routes:
            raise CustomTemplateError(f"route_duplicate:{method}:{path}")
        seen_ids.add(endpoint_id)
        seen_routes.add(route_key)

        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        content_type = _normalize_content_type(item.get("content_type") or response.get("content_type"))
        status_raw = response.get("status", item.get("status"))
        try:
            status = int(status_raw if status_raw not in (None, "") else (201 if method == "POST" else 200))
        except Exception:
            raise CustomTemplateError(f"status_invalid:{endpoint_id}")
        if not (100 <= status <= 599):
            raise CustomTemplateError(f"status_invalid:{endpoint_id}")

        body = response.get("body", item.get("body", {"ok": True}))
        if content_type == "application/json":
            if not isinstance(body, (dict, list, str, int, float, bool)) and body is not None:
                raise CustomTemplateError(f"body_invalid:{endpoint_id}")
            if _json_size(body) > MAX_BODY_BYTES:
                raise CustomTemplateError(f"body_too_large:{endpoint_id}")
        else:
            body = str(body if body is not None else "")
            if len(body.encode("utf-8")) > MAX_BODY_BYTES:
                raise CustomTemplateError(f"body_too_large:{endpoint_id}")

        endpoints.append(
            {
                "id": endpoint_id,
                "method": method,
                "path": path,
                "description": str(item.get("description") or "").strip()[:MAX_DESCRIPTION_CHARS],
                "enabled": bool(item.get("enabled", True)),
                "auth": _normalize_auth(item.get("auth")),
                "response": {
                    "status": status,
                    "content_type": content_type,
                    "headers": _normalize_headers(response.get("headers", item.get("headers"))),
                    "body": body,
                },
            }
        )

    return {
        "id": template_id,
        "name": name,
        "description": description,
        "default_response_profile_id": default_response_profile_id,
        "endpoints": endpoints,
    }


def auth_warnings(payload: dict[str, Any]) -> list[str]:
    endpoints = [item for item in payload.get("endpoints") or [] if bool(item.get("enabled", True))]
    modes = {str((item.get("auth") or {}).get("mode") or "none") for item in endpoints}
    warnings: list[str] = []
    if "bearer_required" in modes and "token_issuer" not in modes:
        warnings.append("Bearer auth is required by at least one endpoint, but this API has no Bearer token issuer.")
    if "api_key_required" in modes and "api_key_issuer" not in modes:
        warnings.append("API key auth is required by at least one endpoint, but this API has no API key issuer.")
    return warnings


def list_templates(conn: sqlite3.Connection, *, enabled_only: bool = False) -> list[dict[str, Any]]:
    ensure_tables(conn)
    sql = f"SELECT template_id, name, description, payload_json, enabled, created_at, updated_at FROM {TABLE_NAME}"
    if enabled_only:
        sql += " WHERE enabled=1"
    sql += " ORDER BY updated_at DESC, template_id ASC"
    out: list[dict[str, Any]] = []
    for row in conn.execute(sql).fetchall():
        try:
            payload = json.loads(str(row["payload_json"] or "{}"))
            payload = normalize_template_payload(payload, existing_template_id=str(row["template_id"]))
        except Exception:
            continue
        payload["enabled"] = bool(int(row["enabled"] or 0))
        payload["created_at"] = row["created_at"]
        payload["updated_at"] = row["updated_at"]
        out.append(payload)
    return out


def get_template(conn: sqlite3.Connection, template_id: str) -> Optional[dict[str, Any]]:
    ensure_tables(conn)
    row = conn.execute(
        f"SELECT template_id, payload_json, enabled, created_at, updated_at FROM {TABLE_NAME} WHERE template_id=?",
        (str(template_id or "").strip(),),
    ).fetchone()
    if not row:
        return None
    payload = normalize_template_payload(json.loads(str(row["payload_json"] or "{}")), existing_template_id=str(row["template_id"]))
    payload["enabled"] = bool(int(row["enabled"] or 0))
    payload["created_at"] = row["created_at"]
    payload["updated_at"] = row["updated_at"]
    return payload


def save_template(conn: sqlite3.Connection, raw_payload: dict[str, Any]) -> dict[str, Any]:
    ensure_tables(conn)
    existing_count = conn.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}").fetchone()[0]
    existing_id = str(raw_payload.get("id") or raw_payload.get("template_id") or "").strip()
    if int(existing_count or 0) >= MAX_TEMPLATES:
        row = conn.execute(f"SELECT 1 FROM {TABLE_NAME} WHERE template_id=?", (existing_id,)).fetchone() if existing_id else None
        if row is None:
            raise CustomTemplateError("templates_limit_reached")
    payload = normalize_template_payload(raw_payload, existing_template_id=existing_id or None)
    now = utc_now_iso()
    conn.execute(
        f"""
        INSERT INTO {TABLE_NAME}(template_id, name, description, payload_json, enabled, created_at, updated_at)
        VALUES(?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(template_id) DO UPDATE SET
          name=excluded.name,
          description=excluded.description,
          payload_json=excluded.payload_json,
          enabled=1,
          updated_at=excluded.updated_at
        """,
        (
            payload["id"],
            payload["name"],
            payload["description"],
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            now,
            now,
        ),
    )
    conn.commit()
    payload["enabled"] = True
    payload["updated_at"] = now
    return payload


def validate_template_against_registry(payload: dict[str, Any], registry: CatalogRegistry) -> None:
    template_id = str(payload.get("id") or "").strip()
    for item in payload.get("endpoints") or []:
        existing = registry.get_endpoint_by_path(str(item.get("method") or ""), str(item.get("path") or ""))
        if existing is None:
            continue
        if template_id and str(existing.id).startswith(f"{template_id}_"):
            continue
        # Custom templates are allowed to shadow built-in public API routes.
        # Reserved panel/health/static routes are blocked earlier by path validation.
        if not str(existing.id).startswith(CUSTOM_PREFIX):
            continue
        raise CustomTemplateError(f"route_conflict:{item.get('method')}:{item.get('path')}:{existing.id}")


def delete_template(conn: sqlite3.Connection, template_id: str) -> bool:
    ensure_tables(conn)
    cur = conn.execute(f"DELETE FROM {TABLE_NAME} WHERE template_id=?", (str(template_id or "").strip(),))
    conn.commit()
    return bool(cur.rowcount)


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=3)
    conn.row_factory = sqlite3.Row
    return conn


def load_templates_from_db(db_path: str) -> list[dict[str, Any]]:
    if not db_path:
        return []
    try:
        conn = _connect(db_path)
        try:
            return list_templates(conn, enabled_only=True)
        finally:
            conn.close()
    except Exception:
        return []


def catalog_version(db_path: str) -> str:
    """Return a cheap DB-backed version for the custom template catalog.

    Runtime providers live in separate processes from the admin panel in the
    production stack. They use this fingerprint to detect that custom templates
    changed in SQLite and reload their in-memory catalog without a restart.
    """
    if not db_path:
        return ""
    try:
        conn = _connect(db_path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (TABLE_NAME,),
            ).fetchone()
            if not exists:
                return "missing"
            rows = conn.execute(
                f"""
                SELECT template_id, updated_at, enabled, LENGTH(payload_json) AS payload_len
                FROM {TABLE_NAME}
                ORDER BY template_id ASC
                """
            ).fetchall()
            return json.dumps(
                [
                    [
                        str(row["template_id"] or ""),
                        str(row["updated_at"] or ""),
                        int(row["enabled"] or 0),
                        int(row["payload_len"] or 0),
                    ]
                    for row in rows
                ],
                separators=(",", ":"),
            )
        finally:
            conn.close()
    except Exception:
        return "unavailable"


def register_custom_templates(registry: CatalogRegistry, *, db_path: str) -> None:
    for template in load_templates_from_db(db_path):
        try:
            group_id = f"{template['id']}_group"
            endpoint_ids: list[str] = []
            for item in template["endpoints"]:
                if not bool(item.get("enabled", True)):
                    continue
                endpoint_id = item["id"]
                endpoint = EndpointDefinition(
                    id=endpoint_id,
                    method=HttpMethod(item["method"]),
                    path_pattern=item["path"],
                    operation_type=_operation_for(item["method"], item["path"]),
                    surface_type=SurfaceType.PUBLIC_API,
                    resource_type=ResourceType.GENERIC,
                    sensitivity_level=SensitivityLevel.MEDIUM,
                    default_response_profile_id=str(template.get("default_response_profile_id") or DEFAULT_RESPONSE_PROFILE_ID),
                    supported_flaw_profile_ids=(),
                    tags=("custom", template["id"]),
                    include_in_schema=True,
                    description=item.get("description") or f"{item['method']} {item['path']}",
                )
                registry.register_endpoint(endpoint)
                endpoint_ids.append(endpoint_id)

            if not endpoint_ids:
                continue
            registry.register_group(
                EndpointGroupDefinition(
                    id=group_id,
                    name=template["name"],
                    endpoint_ids=tuple(endpoint_ids),
                    description=template.get("description") or "Custom API endpoints.",
                )
            )
            registry.register_template(
                BaseTemplateDefinition(
                    id=template["id"],
                    name=template["name"],
                    description=template.get("description") or "Custom API template.",
                    endpoint_group_ids=(group_id,),
                    default_response_profile_id=str(template.get("default_response_profile_id") or DEFAULT_RESPONSE_PROFILE_ID),
                    default_flaw_profile_id=None,
                    compatible_extension_ids=(),
                )
            )
        except Exception as exc:
            logger.warning("Skipping invalid custom API template %s: %s", template.get("id"), exc)


def is_custom_endpoint_id(endpoint_id: str) -> bool:
    return str(endpoint_id or "").startswith(CUSTOM_PREFIX)


def response_for_endpoint(db_path: str, endpoint_id: str) -> Optional[dict[str, Any]]:
    endpoint_id = str(endpoint_id or "").strip()
    if not endpoint_id:
        return None
    for template in load_templates_from_db(db_path):
        for item in template.get("endpoints") or []:
            if item.get("id") == endpoint_id and bool(item.get("enabled", True)):
                return copy.deepcopy(item.get("response") or {})
    return None


def endpoint_spec_for_endpoint(db_path: str, endpoint_id: str) -> Optional[dict[str, Any]]:
    endpoint_id = str(endpoint_id or "").strip()
    if not endpoint_id:
        return None
    for template in load_templates_from_db(db_path):
        for item in template.get("endpoints") or []:
            if item.get("id") == endpoint_id and bool(item.get("enabled", True)):
                return copy.deepcopy(item)
    return None


def extract_path_params(path_pattern: str, actual_path: str) -> dict[str, str]:
    pattern_parts = str(path_pattern or "").rstrip("/").split("/")
    path_parts = str(actual_path or "").rstrip("/").split("/")
    params: dict[str, str] = {}
    if len(pattern_parts) != len(path_parts):
        return params
    for pattern, value in zip(pattern_parts, path_parts):
        if pattern.startswith("{") and pattern.endswith("}") and len(pattern) > 2:
            params[pattern[1:-1]] = value
    return params


def _render_string(value: str, *, context: dict[str, Any]) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(1).strip()
        if token == "random_hex":
            return secrets.token_hex(8)
        if token == "timestamp":
            return utc_now_iso()
        if token in {"request_id", "actor_id"}:
            return str(context.get(token) or "")
        if token.startswith("issued."):
            return str((context.get("issued") or {}).get(token.split(".", 1)[1], ""))
        if token.startswith("path."):
            return str((context.get("path") or {}).get(token.split(".", 1)[1], ""))
        return match.group(0)

    return _PLACEHOLDER_RE.sub(repl, value)


def render_body(value: Any, *, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _render_string(value, context=context)
    if isinstance(value, list):
        return [render_body(item, context=context) for item in value]
    if isinstance(value, dict):
        return {str(key): render_body(item, context=context) for key, item in value.items()}
    return value
