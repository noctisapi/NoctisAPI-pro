"""Value types and enumerations for the catalog layer.

These are the vocabulary of the domain. Nothing here depends on
external services, DB, or env vars.
"""
from __future__ import annotations
from enum import Enum


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class OperationType(str, Enum):
    """Semantic classification of what an endpoint *does*.

    This is the axis used to validate flaw compatibility and derive
    scoring hints for the events pipeline.
    """
    # Auth flows
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_REFRESH = "auth_refresh"
    AUTH_REGISTER = "auth_register"
    AUTH_MFA = "auth_mfa"
    AUTH_PASSWORD_RESET = "auth_password_reset"
    AUTH_TOKEN_REQUEST = "auth_token_request"

    # CRUD
    OBJECT_READ = "object_read"
    OBJECT_CREATE = "object_create"
    OBJECT_UPDATE = "object_update"
    OBJECT_DELETE = "object_delete"
    COLLECTION_LIST = "collection_list"

    # Files
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"

    # Admin / internal
    ADMIN_ACTION = "admin_action"
    SYSTEM_CONFIG = "system_config"
    SYSTEM_EXEC = "system_exec"

    # Recon / passive exposure
    RECON = "recon"

    # Data pipelines
    EXPORT = "export"
    IMPORT_OP = "import_op"
    WEBHOOK_RECEIVE = "webhook_receive"

    # Infrastructure
    HEALTH_CHECK = "health_check"
    SECRET_ACCESS = "secret_access"
    BACKUP_ACCESS = "backup_access"


class SurfaceType(str, Enum):
    """Exposure surface: who is expected to call this endpoint."""
    PUBLIC_API = "public_api"   # Internet-facing business API
    ADMIN = "admin"             # Admin panel / backoffice
    INTERNAL = "internal"       # Internal microservice mesh
    DEBUG = "debug"             # Debug / dev-only (should never be exposed)
    DEVOPS = "devops"           # CI/CD webhooks, pipelines
    RECON = "recon"             # Exposed by mistake (/.env, /config.json…)


class ResourceType(str, Enum):
    """What kind of data/object the endpoint operates on."""
    USER = "user"
    ORDER = "order"
    PAYMENT = "payment"
    PRODUCT = "product"
    FILE = "file"
    CREDENTIAL = "credential"
    CONFIG = "config"
    SECRET = "secret"
    BACKUP = "backup"
    TOKEN = "token"
    SESSION = "session"
    AUDIT_LOG = "audit_log"
    WEBHOOK = "webhook"
    PIPELINE = "pipeline"
    FEATURE_FLAG = "feature_flag"
    CLOUD_METADATA = "cloud_metadata"
    GENERIC = "generic"


class SensitivityLevel(str, Enum):
    """How dangerous is access to this endpoint."""
    LOW = "low"         # Benign recon (health, openapi)
    MEDIUM = "medium"   # Auth, business data
    HIGH = "high"       # Admin, internal, data export
    CRITICAL = "critical"  # Secrets, RCE, cloud metadata


class Difficulty(str, Enum):
    """How realistic / convincing the honeypot responses are."""
    BASIC = "basic"         # Sparse, obvious fake
    MEDIUM = "medium"       # Plausible structure, moderate detail
    ADVANCED = "advanced"   # Highly realistic, rich data


class FlawKind(str, Enum):
    """Classification of security vulnerability being simulated."""
    IDOR = "idor"                      # Insecure Direct Object Reference
    SQLI_HINT = "sqli_hint"            # SQL injection hints in errors
    PATH_TRAVERSAL = "path_traversal"  # Directory traversal
    SSRF = "ssrf"                      # Server-Side Request Forgery hints
    RCE_HINT = "rce_hint"              # Remote Code Execution hints
    LFI = "lfi"                        # Local File Inclusion
    MASS_ASSIGNMENT = "mass_assignment"  # Accepts extra fields silently
    BROKEN_AUTH = "broken_auth"        # Accepts any/no credentials
    EXCESSIVE_DATA = "excessive_data"  # Returns more data than requested
    JWT_WEAK = "jwt_weak"              # Weak JWT signing hints
    NONE = "none"                      # No flaw (explicitly disabled)
