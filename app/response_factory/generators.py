"""Payload generators for each operation_type.

Each generator returns a plain Python dict/list/str that becomes the
response body. They are pure functions of:
  - operation_type / resource_type (from EffectiveEndpoint)
  - difficulty (from ResponseProfile)
  - a seeded Random instance (for determinism)

DETERMINISM RULE:
  The seed is derived from: endpoint_id + UTC date (YYYY-MM-DD).
  Same endpoint_id on the same calendar day → same structural payload.
  This makes the honeypot consistent across requests without storing state.

DIFFICULTY:
  BASIC    → sparse, 2-4 fields, no timestamps, no pagination
  MEDIUM   → realistic, 6-10 fields, ISO timestamps, pagination metadata
  ADVANCED → rich, 12+ fields, nested objects, pagination + links + rate-limit headers

No DB access. No imports from honeypot_public or panel_mvp.
"""
from __future__ import annotations

import hashlib
import random
import string
import uuid
from datetime import datetime, time as dt_time, timezone, timedelta
from typing import Any, Optional

from app.catalog.types import Difficulty, OperationType, ResourceType


# ── Seeding ───────────────────────────────────────────────────────────────────

def _make_rng(endpoint_id: str, salt: str = "") -> random.Random:
    """Return a seeded Random that produces consistent outputs for today."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    seed_bytes = hashlib.sha256(f"{endpoint_id}:{day}:{salt}".encode()).digest()
    seed = int.from_bytes(seed_bytes[:8], "big")
    return random.Random(seed)


def _today_utc_date():
    return datetime.now(timezone.utc).date()


# ── Fake data helpers ─────────────────────────────────────────────────────────

def _fake_uuid(rng: random.Random) -> str:
    # Deterministic UUID-shaped string
    hex_ = format(rng.getrandbits(128), "032x")
    return f"{hex_[:8]}-{hex_[8:12]}-4{hex_[13:16]}-{hex_[16:20]}-{hex_[20:32]}"


def _fake_email(rng: random.Random) -> str:
    names = ["alice", "bob", "charlie", "dana", "eve", "frank", "grace", "henry"]
    domains = ["example.com", "corp.internal", "acme.io", "testorg.net"]
    return f"{rng.choice(names)}{rng.randint(1, 99)}@{rng.choice(domains)}"


def _fake_jwt(rng: random.Random) -> str:
    header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    # Random-ish payload and signature section (not a real JWT)
    payload_chars = string.ascii_letters + string.digits + "_-"
    payload = "".join(rng.choices(payload_chars, k=80))
    sig = "".join(rng.choices(payload_chars, k=64))
    return f"{header}.{payload}.{sig}"


def _fake_iso_ts(rng: random.Random, days_ago: int = 30) -> str:
    day_offset = rng.randint(0, max(0, int(days_ago)))
    second_of_day = rng.randint(0, 86399)
    base_date = _today_utc_date() - timedelta(days=day_offset)
    base = datetime.combine(base_date, dt_time.min, tzinfo=timezone.utc) + timedelta(seconds=second_of_day)
    return base.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fake_future_iso_ts(rng: random.Random, min_days: int = 1, max_days: int = 7) -> str:
    future_days = rng.randint(int(min_days), int(max_days))
    second_of_day = rng.randint(0, 86399)
    base_date = _today_utc_date() + timedelta(days=future_days)
    base = datetime.combine(base_date, dt_time.min, tzinfo=timezone.utc) + timedelta(seconds=second_of_day)
    return base.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fake_id(rng: random.Random, prefix: str = "", length: int = 8) -> str:
    chars = string.ascii_lowercase + string.digits
    suffix = "".join(rng.choices(chars, k=length))
    return f"{prefix}{suffix}" if prefix else suffix


def _fake_amount(rng: random.Random) -> float:
    return round(rng.uniform(1.0, 9999.99), 2)


def _fake_password_hash(rng: random.Random) -> str:
    """Realistic-looking bcrypt hash."""
    chars = string.ascii_letters + string.digits + "./"
    body = "".join(rng.choices(chars, k=53))
    return f"$2b$12${body}"


def _fake_api_key(rng: random.Random) -> str:
    chars = string.ascii_letters + string.digits
    return "sk_live_" + "".join(rng.choices(chars, k=32))


def _fake_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


# ── User object ───────────────────────────────────────────────────────────────

def _user_object(rng: random.Random, difficulty: Difficulty, user_id: Optional[str] = None) -> dict:
    uid = user_id or _fake_id(rng, "usr_")
    base = {
        "id": uid,
        "email": _fake_email(rng),
        "role": rng.choice(["user", "admin", "moderator"]),
    }
    if difficulty == Difficulty.BASIC:
        return base
    base.update({
        "username": _fake_id(rng, "", 8),
        "status": rng.choice(["active", "suspended", "pending"]),
        "created_at": _fake_iso_ts(rng, 365),
        "updated_at": _fake_iso_ts(rng, 30),
        "verified": rng.choice([True, False]),
    })
    if difficulty == Difficulty.ADVANCED:
        base.update({
            "last_login_at": _fake_iso_ts(rng, 7),
            "login_count": rng.randint(1, 500),
            "ip_address": _fake_ip(rng),
            "plan": rng.choice(["free", "pro", "enterprise"]),
            "mfa_enabled": rng.choice([True, False]),
            "permissions": rng.sample(["read", "write", "delete", "admin"], k=rng.randint(1, 3)),
        })
    return base


# ── Order object ──────────────────────────────────────────────────────────────

def _order_object(rng: random.Random, difficulty: Difficulty, order_id: Optional[str] = None) -> dict:
    oid = order_id or _fake_id(rng, "ord_")
    base = {
        "id": oid,
        "status": rng.choice(["pending", "confirmed", "shipped", "delivered", "cancelled"]),
        "total": _fake_amount(rng),
    }
    if difficulty == Difficulty.BASIC:
        return base
    base.update({
        "currency": "USD",
        "customer_id": _fake_id(rng, "usr_"),
        "created_at": _fake_iso_ts(rng, 90),
        "updated_at": _fake_iso_ts(rng, 10),
        "items_count": rng.randint(1, 10),
    })
    if difficulty == Difficulty.ADVANCED:
        base.update({
            "shipping_address": {
                "street": f"{rng.randint(1,999)} Main St",
                "city": rng.choice(["New York", "London", "Paris", "Berlin"]),
                "postal_code": f"{rng.randint(10000,99999)}",
                "country": "US",
            },
            "payment_method": rng.choice(["card", "paypal", "bank_transfer"]),
            "tracking_id": _fake_id(rng, "TRK", 12).upper(),
            "discount": round(rng.uniform(0, 50), 2),
            "tax": round(rng.uniform(0, 100), 2),
        })
    return base


# ── Generic object (for unmapped resource types) ──────────────────────────────

def _generic_object(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    prefix = resource_type.value[:3] + "_"
    base = {"id": _fake_id(rng, prefix), "status": "active"}
    if difficulty != Difficulty.BASIC:
        base.update({
            "created_at": _fake_iso_ts(rng, 180),
            "updated_at": _fake_iso_ts(rng, 30),
        })
    return base


# ── Paginated list wrapper ────────────────────────────────────────────────────

def _paginated_list(
    items: list,
    rng: random.Random,
    difficulty: Difficulty,
    total_hint: Optional[int] = None,
) -> dict:
    total = total_hint or rng.randint(len(items), len(items) * 10 + 5)
    base: dict[str, Any] = {"data": items, "total": total}
    if difficulty != Difficulty.BASIC:
        base.update({"page": 1, "per_page": len(items)})
    if difficulty == Difficulty.ADVANCED:
        base.update({
            "pages": max(1, total // len(items)),
            "has_next": total > len(items),
            "has_prev": False,
        })
    return base


# ── Generators per operation_type ─────────────────────────────────────────────

def gen_auth_login(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    base = {
        "access_token": _fake_jwt(rng),
        "token_type": "bearer",
    }
    if difficulty == Difficulty.BASIC:
        return base
    base.update({
        "expires_in": 3600,
        "user": _user_object(rng, difficulty),
    })
    if difficulty == Difficulty.ADVANCED:
        base.update({
            "refresh_token": _fake_jwt(rng),
            "scope": "read write",
            "issued_at": _fake_iso_ts(rng, 0),
        })
    return base


def gen_auth_register(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    base = {"message": "Account created", "id": _fake_id(rng, "usr_")}
    if difficulty == Difficulty.BASIC:
        return base
    base.update({
        "user": _user_object(rng, difficulty),
        "verification_email_sent": True,
    })
    return base


def gen_auth_mfa(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    base = {"status": "verified"}
    if difficulty != Difficulty.BASIC:
        base.update({
            "session_token": _fake_jwt(rng),
            "expires_in": 300,
        })
    return base


def gen_auth_password_reset(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    base = {"message": "If the email exists, a reset link was sent."}
    if difficulty == Difficulty.ADVANCED:
        base.update({"request_id": _fake_id(rng, "req_"), "expires_in": 900})
    return base


def gen_auth_token_request(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    return gen_auth_login(rng, difficulty, resource_type)


def gen_object_read(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    if resource_type == ResourceType.USER:
        return _user_object(rng, difficulty)
    if resource_type == ResourceType.ORDER:
        return _order_object(rng, difficulty)
    return _generic_object(rng, difficulty, resource_type)


def gen_object_create(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    obj = gen_object_read(rng, difficulty, resource_type)
    if difficulty != Difficulty.BASIC:
        obj["created_at"] = _fake_iso_ts(rng, 0)
    return obj


def gen_object_update(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    obj = gen_object_read(rng, difficulty, resource_type)
    if difficulty != Difficulty.BASIC:
        obj["updated_at"] = _fake_iso_ts(rng, 0)
    return obj


def gen_object_delete(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    return {"deleted": True, "id": _fake_id(rng)}


def gen_collection_list(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    count = {Difficulty.BASIC: 2, Difficulty.MEDIUM: 5, Difficulty.ADVANCED: 10}.get(difficulty, 5)
    items = [gen_object_read(rng, difficulty, resource_type) for _ in range(count)]
    return _paginated_list(items, rng, difficulty)


def gen_admin_action(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    if resource_type == ResourceType.USER:
        count = {Difficulty.BASIC: 3, Difficulty.MEDIUM: 8, Difficulty.ADVANCED: 20}.get(difficulty, 8)
        items = [_user_object(rng, difficulty) for _ in range(count)]
        return _paginated_list(items, rng, difficulty, total_hint=rng.randint(50, 500))
    if resource_type == ResourceType.AUDIT_LOG:
        count = {Difficulty.BASIC: 3, Difficulty.MEDIUM: 10, Difficulty.ADVANCED: 25}.get(difficulty, 10)
        actions = ["login", "logout", "update_user", "delete_record", "export_data", "change_password"]
        items = [
            {
                "id": _fake_id(rng, "log_"),
                "action": rng.choice(actions),
                "user_id": _fake_id(rng, "usr_"),
                "ip": _fake_ip(rng),
                "ts": _fake_iso_ts(rng, 30),
            }
            for _ in range(count)
        ]
        return _paginated_list(items, rng, difficulty)
    # Generic admin view
    return {"status": "ok", "items": [], "count": 0}


def gen_secret_access(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    """Generates convincingly fake secrets. These are all synthetic — not real credentials."""
    base: dict[str, Any] = {
        "DATABASE_URL": f"postgresql://admin:{_fake_id(rng,'',12)}@db.internal:5432/production",
        "JWT_SECRET_KEY": _fake_id(rng, "", 40),
    }
    if difficulty == Difficulty.BASIC:
        return base
    base.update({
        "STRIPE_SECRET_KEY": f"sk_live_{_fake_id(rng,'',32)}",
        "AWS_ACCESS_KEY_ID": "AKIA" + "".join(rng.choices(string.ascii_uppercase + string.digits, k=16)),
        "AWS_SECRET_ACCESS_KEY": _fake_id(rng, "", 40),
        "REDIS_URL": f"redis://:password@redis.internal:6379/0",
    })
    if difficulty == Difficulty.ADVANCED:
        base.update({
            "SENDGRID_API_KEY": f"SG.{_fake_id(rng,'',22)}.{_fake_id(rng,'',43)}",
            "GITHUB_TOKEN": f"ghp_{_fake_id(rng,'',36)}",
            "ENCRYPTION_KEY": _fake_id(rng, "", 64),
            "ADMIN_PASSWORD_HASH": _fake_password_hash(rng),
            "INTERNAL_API_KEY": _fake_api_key(rng),
        })
    return base


def gen_backup_access(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict | list:
    if resource_type == ResourceType.BACKUP:
        count = {Difficulty.BASIC: 2, Difficulty.MEDIUM: 5, Difficulty.ADVANCED: 10}.get(difficulty, 5)
        items = []
        base_date = _today_utc_date()
        for i in range(count):
            date = (base_date - timedelta(days=i)).strftime("%Y-%m-%d")
            item: dict[str, Any] = {
                "id": f"backup-{date}",
                "size_bytes": rng.randint(10_000_000, 500_000_000),
                "created_at": f"{date}T02:00:00Z",
            }
            if difficulty != Difficulty.BASIC:
                item.update({
                    "type": rng.choice(["full", "incremental"]),
                    "status": "completed",
                    "download_url": f"/backup/download/backup-{date}",
                })
            if difficulty == Difficulty.ADVANCED:
                item.update({
                    "checksum": hashlib.sha256(f"backup-{date}".encode()).hexdigest(),
                    "encrypted": True,
                    "storage": rng.choice(["s3", "gcs", "local"]),
                })
            items.append(item)
        return {"backups": items, "count": len(items)}
    return {"status": "ok"}


def gen_recon(
    rng: random.Random,
    difficulty: Difficulty,
    resource_type: ResourceType,
    *,
    endpoint_id: str = "",
) -> str | dict:
    """Returns a text/plain fake env or config file."""
    if endpoint_id == "recon_openapi":
        return {
            "openapi": "3.0.3",
            "info": {
                "title": "Platform API",
                "version": "2.8.1",
            },
            "paths": {
                "/auth/login": {"post": {"summary": "Authenticate user"}},
                "/api/v1/users": {"get": {"summary": "List users"}},
                "/admin/secrets": {"get": {"summary": "Internal secrets"}},
            },
        }
    if endpoint_id == "recon_config":
        return {
            "service": "platform-api",
            "region": "eu-west-1",
            "auth": {
                "issuer": "https://platform-api.duckdns.org",
                "jwks": "/.well-known/jwks.json",
                "audience": "platform-api",
            },
            "features": {"beta_access": True, "sandbox_mode": False, "webhooks": True},
            "contact": {"support": "support@platform-api.duckdns.org"},
        }
    if resource_type == ResourceType.CONFIG:
        lines = [
            f"DB_HOST=db.internal",
            f"DB_PORT=5432",
            f"DB_USER=app_user",
            f"DB_PASS={_fake_id(rng,'',16)}",
            f"DB_NAME=production",
            f"JWT_SECRET={_fake_id(rng,'',32)}",
            f"APP_ENV=production",
        ]
        if difficulty != Difficulty.BASIC:
            lines += [
                f"REDIS_URL=redis://:{_fake_id(rng,'',12)}@redis:6379/0",
                f"STRIPE_SECRET_KEY=sk_live_{_fake_id(rng,'',32)}",
                f"SENDGRID_API_KEY=SG.{_fake_id(rng,'',22)}.{_fake_id(rng,'',43)}",
                f"APP_DEBUG=false",
                f"SENTRY_DSN=https://{_fake_id(rng,'',32)}@sentry.io/{rng.randint(1000000,9999999)}",
            ]
        if difficulty == Difficulty.ADVANCED:
            lines += [
                f"AWS_ACCESS_KEY_ID=AKIA{''.join(rng.choices(string.ascii_uppercase+string.digits, k=16))}",
                f"AWS_SECRET_ACCESS_KEY={_fake_id(rng,'',40)}",
                f"ENCRYPTION_KEY={_fake_id(rng,'',64)}",
            ]
        return "\n".join(lines)
    # Generic recon: JSON config
    return str({
        "version": "1.0",
        "env": "production",
        "debug": False,
        "db_host": "db.internal",
    })


def gen_file_upload(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    base = {"id": _fake_id(rng, "file_"), "status": "uploaded"}
    if difficulty != Difficulty.BASIC:
        base.update({
            "url": f"/files/{base['id']}/download",
            "size_bytes": rng.randint(1024, 10_000_000),
            "created_at": _fake_iso_ts(rng, 0),
        })
    if difficulty == Difficulty.ADVANCED:
        base.update({
            "content_type": "application/octet-stream",
            "checksum": hashlib.sha256(base["id"].encode()).hexdigest(),
            "scan_status": "clean",
        })
    return base


def gen_file_download(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    file_id = _fake_id(rng, "file_")
    base = {"id": file_id, "name": f"document_{rng.randint(1,999)}.pdf"}
    if difficulty != Difficulty.BASIC:
        base.update({
            "size_bytes": rng.randint(1024, 10_000_000),
            "content_type": "application/pdf",
            "created_at": _fake_iso_ts(rng, 30),
            "download_url": f"/files/{file_id}/download",
        })
    return base


def gen_export(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    return {
        "export_id": _fake_id(rng, "exp_"),
        "status": "processing",
        "download_url": f"/exports/{_fake_id(rng,'',16)}",
        "expires_at": _fake_future_iso_ts(rng, 1, 7),
    }


def gen_webhook_receive(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    return {"status": "accepted", "id": _fake_id(rng, "evt_")}


def gen_system_config(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    base = {"status": "ok", "version": "2.4.1"}
    if difficulty != Difficulty.BASIC:
        base.update({
            "feature_flags": {
                "new_ui": True,
                "beta_api": False,
                "dark_mode": True,
            },
            "maintenance_mode": False,
        })
    return base


def gen_health_check(rng: random.Random, difficulty: Difficulty, resource_type: ResourceType) -> dict:
    return {"status": "ok"}


# ── Default status code per operation_type ────────────────────────────────────

_DEFAULT_STATUS: dict[OperationType, int] = {
    OperationType.AUTH_LOGIN: 200,
    OperationType.AUTH_LOGOUT: 200,
    OperationType.AUTH_REFRESH: 200,
    OperationType.AUTH_REGISTER: 201,
    OperationType.AUTH_MFA: 200,
    OperationType.AUTH_PASSWORD_RESET: 200,
    OperationType.AUTH_TOKEN_REQUEST: 200,
    OperationType.OBJECT_READ: 200,
    OperationType.OBJECT_CREATE: 201,
    OperationType.OBJECT_UPDATE: 200,
    OperationType.OBJECT_DELETE: 200,
    OperationType.COLLECTION_LIST: 200,
    OperationType.FILE_UPLOAD: 201,
    OperationType.FILE_DOWNLOAD: 200,
    OperationType.ADMIN_ACTION: 200,
    OperationType.SYSTEM_CONFIG: 200,
    OperationType.SYSTEM_EXEC: 200,
    OperationType.RECON: 200,
    OperationType.EXPORT: 202,
    OperationType.IMPORT_OP: 202,
    OperationType.WEBHOOK_RECEIVE: 202,
    OperationType.HEALTH_CHECK: 200,
    OperationType.SECRET_ACCESS: 200,
    OperationType.BACKUP_ACCESS: 200,
}

# ── Default content_type per operation_type ───────────────────────────────────

_DEFAULT_CONTENT_TYPE: dict[OperationType, str] = {
    OperationType.RECON: "text/plain",
}

# ── Dispatch table ────────────────────────────────────────────────────────────

_GENERATORS: dict[OperationType, Any] = {
    OperationType.AUTH_LOGIN: gen_auth_login,
    OperationType.AUTH_REGISTER: gen_auth_register,
    OperationType.AUTH_MFA: gen_auth_mfa,
    OperationType.AUTH_PASSWORD_RESET: gen_auth_password_reset,
    OperationType.AUTH_TOKEN_REQUEST: gen_auth_token_request,
    OperationType.OBJECT_READ: gen_object_read,
    OperationType.OBJECT_CREATE: gen_object_create,
    OperationType.OBJECT_UPDATE: gen_object_update,
    OperationType.OBJECT_DELETE: gen_object_delete,
    OperationType.COLLECTION_LIST: gen_collection_list,
    OperationType.FILE_UPLOAD: gen_file_upload,
    OperationType.FILE_DOWNLOAD: gen_file_download,
    OperationType.ADMIN_ACTION: gen_admin_action,
    OperationType.SYSTEM_CONFIG: gen_system_config,
    OperationType.RECON: gen_recon,
    OperationType.EXPORT: gen_export,
    OperationType.IMPORT_OP: gen_export,
    OperationType.WEBHOOK_RECEIVE: gen_webhook_receive,
    OperationType.HEALTH_CHECK: gen_health_check,
    OperationType.SECRET_ACCESS: gen_secret_access,
    OperationType.BACKUP_ACCESS: gen_backup_access,
}

SUPPORTED_OPERATION_TYPES: frozenset[OperationType] = frozenset(_GENERATORS.keys())


def generate_payload(
    operation_type: OperationType,
    resource_type: ResourceType,
    difficulty: Difficulty,
    endpoint_id: str,
    salt: str = "",
) -> Any:
    """Dispatch to the correct generator and return the raw payload.

    Returns None if no generator is registered for this operation_type.
    """
    gen_fn = _GENERATORS.get(operation_type)
    if gen_fn is None:
        return None
    rng = _make_rng(endpoint_id, salt)
    if operation_type == OperationType.RECON:
        return gen_recon(rng, difficulty, resource_type, endpoint_id=endpoint_id)
    return gen_fn(rng, difficulty, resource_type)


def default_status_for(operation_type: OperationType) -> int:
    return _DEFAULT_STATUS.get(operation_type, 200)


def default_content_type_for(operation_type: OperationType, endpoint_id: str = "") -> str:
    if endpoint_id in {"recon_config", "recon_openapi"}:
        return "application/json"
    return _DEFAULT_CONTENT_TYPE.get(operation_type, "application/json")
