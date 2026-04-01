"""Runtime package — the resolved, ready-to-use state.

The runtime layer is:
  - Derived: built by builder.build_effective_runtime_config().
  - Ephemeral: rebuilt when config changes, never persisted.
  - The ONLY thing route handlers should touch.

Route handlers MUST NOT import from app.catalog or app.instance_config.
They only call EffectiveRuntimeConfig.get_endpoint().
"""
from app.runtime.models import EffectiveEndpoint, EffectiveRuntimeConfig
from app.runtime.context import InteractionContext, InteractionOutcome
from app.runtime.builder import build_effective_runtime_config, BuildError

__all__ = [
    "EffectiveEndpoint",
    "EffectiveRuntimeConfig",
    "InteractionContext",
    "InteractionOutcome",
    "build_effective_runtime_config",
    "BuildError",
]
