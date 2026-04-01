"""Built-in extension pack definitions.

Extensions are optional additions on top of a template.
They add endpoint groups but cannot remove or override template endpoints
(unless merge_rules.allow_path_override = True).

Dependencies and incompatibilities are validated by the builder.
"""
from app.catalog.definitions import ExtensionPackDefinition, MergeRules

FILE_SERVER_EXT = ExtensionPackDefinition(
    id="file_server_ext",
    name="File Server Extension",
    description=(
        "Adds file upload and download endpoints. "
        "Compatible with any template that involves file operations."
    ),
    endpoint_group_ids=("file_server",),
    dependencies=(),
    incompatible_with=(),
    merge_rules=MergeRules(priority=10),
)

WEBHOOKS_EXT = ExtensionPackDefinition(
    id="webhooks_ext",
    name="Webhook Receivers Extension",
    description=(
        "Adds GitHub and GitLab webhook endpoints. "
        "Useful for templates targeting DevOps/CI-CD attack surfaces."
    ),
    endpoint_group_ids=("webhooks",),
    dependencies=(),
    incompatible_with=(),
    merge_rules=MergeRules(priority=10),
)

# ── Master list ───────────────────────────────────────────────────────────────

ALL_EXTENSIONS = [FILE_SERVER_EXT, WEBHOOKS_EXT]
