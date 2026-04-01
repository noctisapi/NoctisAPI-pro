"""Built-in base template definitions.

Each template represents a *type of application* being simulated.
Templates are mutually exclusive — exactly one is active per instance.
"""
from app.catalog.definitions import BaseTemplateDefinition

# ── Ecommerce ────────────────────────────────────────────────────────────────

ECOMMERCE = BaseTemplateDefinition(
    id="ecommerce",
    name="E-commerce Platform",
    description=(
        "Simulates a typical e-commerce API: auth, user management, "
        "orders, admin panel, and opportunistic recon surfaces. "
        "Default target for retail/marketplace threat modelling."
    ),
    endpoint_group_ids=(
        "auth_flows",
        "user_management",
        "order_management",
        "admin_panel",
        "recon_exposure",
        "critical_traps",
    ),
    default_response_profile_id="standard_medium",
    default_flaw_profile_id="idor_basic",   # Applied to all compatible endpoints by default
    compatible_extension_ids=("file_server_ext", "webhooks_ext"),
)

# ── Corporate SaaS ────────────────────────────────────────────────────────────

CORPORATE_SAAS = BaseTemplateDefinition(
    id="corporate_saas",
    name="Corporate SaaS API",
    description=(
        "Simulates an internal SaaS product with user management, "
        "auth, admin panel, and recon surfaces. No order/payment flows."
    ),
    endpoint_group_ids=(
        "auth_flows",
        "user_management",
        "admin_panel",
        "recon_exposure",
        "critical_traps",
    ),
    default_response_profile_id="standard_medium",
    default_flaw_profile_id=None,
    compatible_extension_ids=("file_server_ext", "webhooks_ext"),
)

# ── Master list ───────────────────────────────────────────────────────────────

ALL_TEMPLATES = [ECOMMERCE, CORPORATE_SAAS]
