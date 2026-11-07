from .client import (  # noqa: F401
    LicenseDecision,
    LicensingClientError,
    LicensingManager,
    LicensingStartupDenied,
    LicensingState,
    compute_client_identity,
    compute_instance_fingerprint_sha256_hex,
    get_default_manager,
    get_or_create_uuid_file,
)
from .feature_flags import (  # noqa: F401
    Feature,
    LicenseTier,
    enabled_features,
    feature_flags,
    get_license_tier,
    has_feature,
    is_pro_enabled,
    set_pro_enabled_provider,
)
from .entitlements import (  # noqa: F401
    EntitlementDecision,
    EntitlementDocument,
    EntitlementValidationError,
    evaluate,
)
from .managed_mode import (  # noqa: F401
    ManagedEntitlementError,
    ManagedEntitlementResult,
    resolve_managed_entitlements,
)
from .commercial import (  # noqa: F401
    BillingEvent,
    BillingEventLedger,
    CommercialRecord,
    CommercialState,
    CommercialTransitionError,
    PlanChange,
    plan_change,
    transition,
    verify_webhook_signature,
)

__all__ = [
    # client
    "LicenseDecision",
    "LicensingClientError",
    "LicensingManager",
    "LicensingStartupDenied",
    "LicensingState",
    "compute_client_identity",
    "compute_instance_fingerprint_sha256_hex",
    "get_default_manager",
    "get_or_create_uuid_file",
    # feature_flags
    "Feature",
    "LicenseTier",
    "enabled_features",
    "feature_flags",
    "get_license_tier",
    "has_feature",
    "is_pro_enabled",
    "set_pro_enabled_provider",
    # entitlements
    "EntitlementDecision",
    "EntitlementDocument",
    "EntitlementValidationError",
    "evaluate",
    # managed_mode
    "ManagedEntitlementError",
    "ManagedEntitlementResult",
    "resolve_managed_entitlements",
    # commercial
    "BillingEvent",
    "BillingEventLedger",
    "CommercialRecord",
    "CommercialState",
    "CommercialTransitionError",
    "PlanChange",
    "plan_change",
    "transition",
    "verify_webhook_signature",
]
