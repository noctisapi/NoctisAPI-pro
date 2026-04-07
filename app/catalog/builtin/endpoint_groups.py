"""Built-in endpoint groups and their member endpoint definitions.

Structure:
  - Define all EndpointDefinitions first (leaf nodes).
  - Then define EndpointGroupDefinitions that reference them.

Naming convention for endpoint ids:   {resource}_{operation}
  e.g.:  users_list, orders_get, auth_login, admin_users_list
"""
from app.catalog.definitions import EndpointDefinition, EndpointGroupDefinition
from app.catalog.types import (
    HttpMethod,
    OperationType,
    ResourceType,
    SensitivityLevel,
    SurfaceType,
)

# ── Auth flow endpoints ───────────────────────────────────────────────────────

AUTH_LOGIN = EndpointDefinition(
    id="auth_login",
    method=HttpMethod.POST,
    path_pattern="/auth/login",
    operation_type=OperationType.AUTH_LOGIN,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.CREDENTIAL,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic", "excessive_data_basic", "sqli_hint_basic"),
    tags=("auth", "credentials"),
    description="Login endpoint. Returns a bearer token when authentication is accepted.",
)

AUTH_REGISTER = EndpointDefinition(
    id="auth_register",
    method=HttpMethod.POST,
    path_pattern="/auth/register",
    operation_type=OperationType.AUTH_REGISTER,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.USER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("excessive_data_basic",),
    description="Registration endpoint. Records actor interest in account creation.",
)

AUTH_MFA = EndpointDefinition(
    id="auth_mfa",
    method=HttpMethod.POST,
    path_pattern="/auth/mfa",
    operation_type=OperationType.AUTH_MFA,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.CREDENTIAL,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic",),
    tags=("auth", "mfa"),
    description="MFA verification endpoint.",
)

AUTH_PASSWORD_RESET = EndpointDefinition(
    id="auth_password_reset",
    method=HttpMethod.POST,
    path_pattern="/auth/forgot",
    operation_type=OperationType.AUTH_PASSWORD_RESET,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.CREDENTIAL,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=(),
    description="Password reset request endpoint.",
)

GROUP_AUTH_FLOWS = EndpointGroupDefinition(
    id="auth_flows",
    name="Authentication Flows",
    endpoint_ids=("auth_login", "auth_register", "auth_mfa", "auth_password_reset"),
    description="Login, registration, MFA, and password reset endpoints.",
)

# ── User management ───────────────────────────────────────────────────────────

USERS_LIST = EndpointDefinition(
    id="users_list",
    method=HttpMethod.GET,
    path_pattern="/api/v1/users",
    operation_type=OperationType.COLLECTION_LIST,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.USER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("idor_basic", "excessive_data_basic", "sqli_hint_basic"),
    description="User list. Returns paginated users.",
)

USERS_GET = EndpointDefinition(
    id="users_get",
    method=HttpMethod.GET,
    path_pattern="/api/v1/users/{user_id}",
    operation_type=OperationType.OBJECT_READ,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.USER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("idor_basic", "idor_advanced", "excessive_data_basic"),
    tags=("users",),
    description="Get user by ID.",
)

USERS_UPDATE = EndpointDefinition(
    id="users_update",
    method=HttpMethod.PATCH,
    path_pattern="/api/v1/users/{user_id}",
    operation_type=OperationType.OBJECT_UPDATE,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.USER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("idor_basic", "idor_advanced"),
    description="Update user profile.",
)

GROUP_USER_MANAGEMENT = EndpointGroupDefinition(
    id="user_management",
    name="User Management",
    endpoint_ids=("users_list", "users_get", "users_update"),
)

# ── Order management (ecommerce) ──────────────────────────────────────────────

ORDERS_LIST = EndpointDefinition(
    id="orders_list",
    method=HttpMethod.GET,
    path_pattern="/api/v1/orders",
    operation_type=OperationType.COLLECTION_LIST,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.ORDER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("idor_basic", "excessive_data_basic"),
    description="Order list endpoint.",
)

ORDERS_GET = EndpointDefinition(
    id="orders_get",
    method=HttpMethod.GET,
    path_pattern="/api/v1/orders/{order_id}",
    operation_type=OperationType.OBJECT_READ,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.ORDER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("idor_basic", "idor_advanced", "excessive_data_basic"),
    tags=("orders",),
    description="Get order by ID.",
)

ORDERS_CREATE = EndpointDefinition(
    id="orders_create",
    method=HttpMethod.POST,
    path_pattern="/api/v1/orders",
    operation_type=OperationType.OBJECT_CREATE,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.ORDER,
    sensitivity_level=SensitivityLevel.MEDIUM,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=(),
    description="Create order endpoint.",
)

GROUP_ORDER_MANAGEMENT = EndpointGroupDefinition(
    id="order_management",
    name="Order Management",
    endpoint_ids=("orders_list", "orders_get", "orders_create"),
)

# ── Admin panel ───────────────────────────────────────────────────────────────

ADMIN_HOME = EndpointDefinition(
    id="admin_home",
    method=HttpMethod.GET,
    path_pattern="/admin",
    operation_type=OperationType.ADMIN_ACTION,
    surface_type=SurfaceType.ADMIN,
    resource_type=ResourceType.GENERIC,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic",),
    tags=("admin",),
    description="Admin home page endpoint.",
)

ADMIN_USERS_LIST = EndpointDefinition(
    id="admin_users_list",
    method=HttpMethod.GET,
    path_pattern="/admin/users",
    operation_type=OperationType.ADMIN_ACTION,
    surface_type=SurfaceType.ADMIN,
    resource_type=ResourceType.USER,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic", "excessive_data_basic"),
    tags=("admin", "users"),
    description="Admin users endpoint.",
)

ADMIN_AUDIT_LOG = EndpointDefinition(
    id="admin_audit_log",
    method=HttpMethod.GET,
    path_pattern="/admin/audit",
    operation_type=OperationType.ADMIN_ACTION,
    surface_type=SurfaceType.ADMIN,
    resource_type=ResourceType.AUDIT_LOG,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic",),
    tags=("admin", "audit"),
    description="Admin audit log endpoint.",
)

GROUP_ADMIN_PANEL = EndpointGroupDefinition(
    id="admin_panel",
    name="Admin Panel",
    endpoint_ids=("admin_home", "admin_users_list", "admin_audit_log"),
)

# ── Recon / accidental exposure ───────────────────────────────────────────────

RECON_ENV = EndpointDefinition(
    id="recon_env",
    method=HttpMethod.GET,
    path_pattern="/.env",
    operation_type=OperationType.RECON,
    surface_type=SurfaceType.RECON,
    resource_type=ResourceType.CONFIG,
    sensitivity_level=SensitivityLevel.CRITICAL,
    default_response_profile_id="standard_basic",
    supported_flaw_profile_ids=(),
    include_in_schema=False,
    tags=("config",),
    description="Environment configuration endpoint.",
)

RECON_CONFIG = EndpointDefinition(
    id="recon_config",
    method=HttpMethod.GET,
    path_pattern="/config.json",
    operation_type=OperationType.RECON,
    surface_type=SurfaceType.RECON,
    resource_type=ResourceType.CONFIG,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_basic",
    supported_flaw_profile_ids=(),
    include_in_schema=False,
    tags=("config",),
    description="Configuration file endpoint.",
)

RECON_OPENAPI = EndpointDefinition(
    id="recon_openapi",
    method=HttpMethod.GET,
    path_pattern="/openapi.json",
    operation_type=OperationType.RECON,
    surface_type=SurfaceType.RECON,
    resource_type=ResourceType.GENERIC,
    sensitivity_level=SensitivityLevel.LOW,
    default_response_profile_id="standard_basic",
    supported_flaw_profile_ids=(),
    include_in_schema=False,
    tags=("openapi",),
    description="OpenAPI specification endpoint.",
)

GROUP_RECON = EndpointGroupDefinition(
    id="recon_exposure",
    name="Recon / Accidental Exposure",
    endpoint_ids=("recon_env", "recon_config", "recon_openapi"),
)

# ── High-value internal endpoints ─────────────────────────────────────────────

SECRETS_ADMIN = EndpointDefinition(
    id="secrets_admin",
    method=HttpMethod.GET,
    path_pattern="/admin/secrets",
    operation_type=OperationType.SECRET_ACCESS,
    surface_type=SurfaceType.INTERNAL,
    resource_type=ResourceType.SECRET,
    sensitivity_level=SensitivityLevel.CRITICAL,
    default_response_profile_id="standard_advanced",
    supported_flaw_profile_ids=("broken_auth_basic", "excessive_data_basic"),
    include_in_schema=False,
    tags=("admin", "secrets"),
    description="Admin secrets endpoint.",
)

BACKUP_LIST = EndpointDefinition(
    id="backup_list",
    method=HttpMethod.GET,
    path_pattern="/backup/list",
    operation_type=OperationType.BACKUP_ACCESS,
    surface_type=SurfaceType.INTERNAL,
    resource_type=ResourceType.BACKUP,
    sensitivity_level=SensitivityLevel.CRITICAL,
    default_response_profile_id="standard_advanced",
    supported_flaw_profile_ids=("broken_auth_basic",),
    include_in_schema=False,
    tags=("backup",),
    description="Backup listing endpoint.",
)

BACKUP_DOWNLOAD = EndpointDefinition(
    id="backup_download",
    method=HttpMethod.GET,
    path_pattern="/backup/download/{backup_id}",
    operation_type=OperationType.BACKUP_ACCESS,
    surface_type=SurfaceType.INTERNAL,
    resource_type=ResourceType.BACKUP,
    sensitivity_level=SensitivityLevel.CRITICAL,
    default_response_profile_id="standard_advanced",
    supported_flaw_profile_ids=("broken_auth_basic", "path_traversal_basic"),
    include_in_schema=False,
    tags=("backup",),
    description="Backup download endpoint.",
)

GROUP_CRITICAL_TRAPS = EndpointGroupDefinition(
    id="critical_traps",
    name="Critical Internal Endpoints",
    endpoint_ids=("secrets_admin", "backup_list", "backup_download"),
)

# ── File server (extension group) ─────────────────────────────────────────────

FILES_UPLOAD = EndpointDefinition(
    id="files_upload",
    method=HttpMethod.POST,
    path_pattern="/files",
    operation_type=OperationType.FILE_UPLOAD,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.FILE,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=(),
    tags=("files",),
    description="File upload endpoint.",
)

FILES_DOWNLOAD = EndpointDefinition(
    id="files_download",
    method=HttpMethod.GET,
    path_pattern="/files/{file_id}/download",
    operation_type=OperationType.FILE_DOWNLOAD,
    surface_type=SurfaceType.PUBLIC_API,
    resource_type=ResourceType.FILE,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("path_traversal_basic",),
    tags=("files",),
    description="File download endpoint.",
)

GROUP_FILE_SERVER = EndpointGroupDefinition(
    id="file_server",
    name="File Server",
    endpoint_ids=("files_upload", "files_download"),
)

# ── Webhook receiver (extension group) ────────────────────────────────────────

WEBHOOKS_GITHUB = EndpointDefinition(
    id="webhooks_github",
    method=HttpMethod.POST,
    path_pattern="/webhooks/github",
    operation_type=OperationType.WEBHOOK_RECEIVE,
    surface_type=SurfaceType.DEVOPS,
    resource_type=ResourceType.WEBHOOK,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic",),
    tags=("webhooks", "devops"),
    description="GitHub webhook receiver.",
)

WEBHOOKS_GITLAB = EndpointDefinition(
    id="webhooks_gitlab",
    method=HttpMethod.POST,
    path_pattern="/webhooks/gitlab",
    operation_type=OperationType.WEBHOOK_RECEIVE,
    surface_type=SurfaceType.DEVOPS,
    resource_type=ResourceType.WEBHOOK,
    sensitivity_level=SensitivityLevel.HIGH,
    default_response_profile_id="standard_medium",
    supported_flaw_profile_ids=("broken_auth_basic",),
    tags=("webhooks", "devops"),
    description="GitLab webhook receiver.",
)

GROUP_WEBHOOKS = EndpointGroupDefinition(
    id="webhooks",
    name="Webhook Receivers",
    endpoint_ids=("webhooks_github", "webhooks_gitlab"),
)

# ── Master list ───────────────────────────────────────────────────────────────

ALL_ENDPOINT_DEFINITIONS = [
    AUTH_LOGIN, AUTH_REGISTER, AUTH_MFA, AUTH_PASSWORD_RESET,
    USERS_LIST, USERS_GET, USERS_UPDATE,
    ORDERS_LIST, ORDERS_GET, ORDERS_CREATE,
    ADMIN_HOME, ADMIN_USERS_LIST, ADMIN_AUDIT_LOG,
    RECON_ENV, RECON_CONFIG, RECON_OPENAPI,
    SECRETS_ADMIN, BACKUP_LIST, BACKUP_DOWNLOAD,
    FILES_UPLOAD, FILES_DOWNLOAD,
    WEBHOOKS_GITHUB, WEBHOOKS_GITLAB,
]

ALL_GROUP_DEFINITIONS = [
    GROUP_AUTH_FLOWS,
    GROUP_USER_MANAGEMENT,
    GROUP_ORDER_MANAGEMENT,
    GROUP_ADMIN_PANEL,
    GROUP_RECON,
    GROUP_CRITICAL_TRAPS,
    GROUP_FILE_SERVER,
    GROUP_WEBHOOKS,
]
