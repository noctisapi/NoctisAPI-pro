"""Domain contracts for the operator Control Center.

The Control Center has its own ``cc_*`` tables and must not become a second
storage location for honeypot traffic, attack events, or panel sessions.
"""

from .model import (
    AUDIT_ACTIONS,
    COMMERCIAL_STATES,
    CONTROL_CENTER_TABLES,
    DEPLOYMENT_STATES,
    DOMAIN_KINDS,
    JOB_STATES,
    JOB_TYPES,
    MODEL_VERSION,
    ControlCenterInvariantError,
    validate_job_request,
)
from .security import (
    AUTHN_LEVELS,
    MFA_LEVELS,
    ControlCenterAccessError,
    ControlCenterPrincipal,
    audit_event,
    authorize,
    sanitize_audit_details,
)
from .router import router
from .ui import router as ui_router
from .repository import (
    ControlCenterReadRepository,
    SQLiteControlCenterReadRepository,
    connect_sqlite,
    open_sqlite_repository,
)
from .ports import (
    AdapterResult,
    BillingAdapter,
    BillingEvent,
    BillingSubscriptionSnapshot,
    DeploymentAdapter,
    DeploymentTarget,
    ProviderObservation,
)
from .adapters import AdapterRegistry, AdapterUnavailableError
from .worker import READ_ONLY_JOB_TYPES, ReadOnlyJobError, ReadOnlyReconciliationWorker
from .provider_adapters import HetznerDeploymentAdapter, ProviderAdapterError

__all__ = [
    "AUDIT_ACTIONS",
    "COMMERCIAL_STATES",
    "CONTROL_CENTER_TABLES",
    "DEPLOYMENT_STATES",
    "DOMAIN_KINDS",
    "JOB_STATES",
    "JOB_TYPES",
    "MODEL_VERSION",
    "ControlCenterInvariantError",
    "validate_job_request",
    "AUTHN_LEVELS",
    "MFA_LEVELS",
    "ControlCenterAccessError",
    "ControlCenterPrincipal",
    "audit_event",
    "authorize",
    "sanitize_audit_details",
    "router",
    "ui_router",
    "ControlCenterReadRepository",
    "SQLiteControlCenterReadRepository",
    "connect_sqlite",
    "open_sqlite_repository",
    "AdapterResult",
    "BillingAdapter",
    "BillingEvent",
    "BillingSubscriptionSnapshot",
    "DeploymentAdapter",
    "DeploymentTarget",
    "ProviderObservation",
    "AdapterRegistry",
    "AdapterUnavailableError",
    "READ_ONLY_JOB_TYPES",
    "ReadOnlyJobError",
    "ReadOnlyReconciliationWorker",
    "HetznerDeploymentAdapter",
    "ProviderAdapterError",
]
