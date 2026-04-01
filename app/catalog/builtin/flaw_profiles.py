"""Built-in security flaw profile definitions.

Each profile represents ONE vulnerability behavior pattern.
The `compatible_operation_types` field is the allow-list checked by the builder.
The `parameters` dict carries flaw-specific knobs used by the response generator.

NOTE: flaw profiles are NOT tied to any template. A template may set a default
flaw, but the same flaw can be applied to endpoints across different templates.
"""
from app.catalog.definitions import SecurityFlawProfileDefinition
from app.catalog.types import FlawKind, OperationType

# ── IDOR ─────────────────────────────────────────────────────────────────────

IDOR_BASIC = SecurityFlawProfileDefinition(
    id="idor_basic",
    name="IDOR – Basic",
    kind=FlawKind.IDOR,
    parameters={
        # Probability (0.0-1.0) of returning a neighbouring object's data
        "leak_probability": 0.6,
        # How many id steps away from the requested id to leak
        "id_offset_range": [1, 5],
    },
    compatible_operation_types=(
        OperationType.OBJECT_READ,
        OperationType.OBJECT_UPDATE,
        OperationType.OBJECT_DELETE,
    ),
    ttp_tags=("T1530", "CWE-284"),
    detection_markers=("cross_user_data_leak", "predictable_id_sequence"),
    description=(
        "Response occasionally returns data belonging to a different object "
        "(sequential ID leak). No auth check on object ownership."
    ),
)

IDOR_ADVANCED = SecurityFlawProfileDefinition(
    id="idor_advanced",
    name="IDOR – Advanced",
    kind=FlawKind.IDOR,
    parameters={
        "leak_probability": 0.9,
        "id_offset_range": [1, 20],
        "expose_owner_field": True,
    },
    compatible_operation_types=(
        OperationType.OBJECT_READ,
        OperationType.OBJECT_UPDATE,
        OperationType.OBJECT_DELETE,
        OperationType.COLLECTION_LIST,
    ),
    ttp_tags=("T1530", "CWE-284"),
    detection_markers=("cross_user_data_leak", "predictable_id_sequence", "owner_field_exposure"),
    description="High-probability IDOR with explicit owner_id field exposed in responses.",
)

# ── SQL injection hints ───────────────────────────────────────────────────────

SQLI_HINT_BASIC = SecurityFlawProfileDefinition(
    id="sqli_hint_basic",
    name="SQLi Hint – Basic",
    kind=FlawKind.SQLI_HINT,
    parameters={
        # Probability of leaking a SQL fragment in an error message
        "hint_probability": 0.4,
        "db_type": "mysql",
        "leak_table_names": False,
    },
    compatible_operation_types=(
        OperationType.COLLECTION_LIST,
        OperationType.OBJECT_READ,
        OperationType.AUTH_LOGIN,
    ),
    ttp_tags=("T1190", "CWE-89"),
    detection_markers=("sql_fragment_in_error", "db_type_disclosure"),
    description=(
        "Error responses occasionally include fragments of SQL queries, "
        "hinting at the underlying DB engine."
    ),
)

# ── Path traversal ────────────────────────────────────────────────────────────

PATH_TRAVERSAL_BASIC = SecurityFlawProfileDefinition(
    id="path_traversal_basic",
    name="Path Traversal – Basic",
    kind=FlawKind.PATH_TRAVERSAL,
    parameters={
        # Files that can be 'read' when traversal succeeds
        "accessible_files": ["/etc/passwd", "/etc/hostname", "/proc/version"],
        "success_probability": 0.7,
    },
    compatible_operation_types=(
        OperationType.FILE_DOWNLOAD,
        OperationType.OBJECT_READ,
    ),
    ttp_tags=("T1083", "CWE-22"),
    detection_markers=("dotdot_sequence", "absolute_path_param", "sensitive_file_content"),
    description="Accepts ../ sequences in path parameters and returns fake sensitive file contents.",
)

# ── Broken auth ───────────────────────────────────────────────────────────────

BROKEN_AUTH_BASIC = SecurityFlawProfileDefinition(
    id="broken_auth_basic",
    name="Broken Auth – Basic",
    kind=FlawKind.BROKEN_AUTH,
    parameters={
        # If True, any token (including 'admin', '1234') is accepted
        "accept_any_token": True,
        # If True, missing Authorization header is silently ignored
        "ignore_missing_auth": False,
    },
    compatible_operation_types=(
        OperationType.OBJECT_READ,
        OperationType.COLLECTION_LIST,
        OperationType.ADMIN_ACTION,
        OperationType.SECRET_ACCESS,
    ),
    ttp_tags=("T1078", "CWE-287"),
    detection_markers=("trivial_token_accepted", "no_signature_check"),
    description="Accepts obviously weak tokens (e.g., 'admin', 'test123') without validation.",
)

# ── Excessive data exposure ───────────────────────────────────────────────────

EXCESSIVE_DATA_BASIC = SecurityFlawProfileDefinition(
    id="excessive_data_basic",
    name="Excessive Data Exposure – Basic",
    kind=FlawKind.EXCESSIVE_DATA,
    parameters={
        # Extra fields added to object responses
        "extra_fields": ["password_hash", "internal_notes", "api_key_preview"],
        "leak_probability": 0.8,
    },
    compatible_operation_types=(
        OperationType.OBJECT_READ,
        OperationType.COLLECTION_LIST,
        OperationType.AUTH_LOGIN,
        OperationType.AUTH_TOKEN_REQUEST,
    ),
    ttp_tags=("T1530", "CWE-213"),
    detection_markers=("sensitive_field_in_response", "hash_pattern", "key_prefix_leak"),
    description="Returns additional sensitive fields (hashes, internal notes) not intended for the caller.",
)

# ── Registry helper ───────────────────────────────────────────────────────────

ALL_FLAW_PROFILES = [
    IDOR_BASIC,
    IDOR_ADVANCED,
    SQLI_HINT_BASIC,
    PATH_TRAVERSAL_BASIC,
    BROKEN_AUTH_BASIC,
    EXCESSIVE_DATA_BASIC,
]
