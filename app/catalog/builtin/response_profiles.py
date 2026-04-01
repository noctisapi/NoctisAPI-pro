"""Built-in response profile definitions.

Naming convention:  {style}_{difficulty}
  style:      standard | verbose | terse | legacy
  difficulty: basic | medium | advanced

Inheritance example:
  standard_basic → standard_medium (child overrides latency + difficulty)
"""
from app.catalog.definitions import ErrorStyleConfig, LatencyConfig, ResponseProfileDefinition
from app.catalog.types import Difficulty

# ── Base profiles (no parent) ─────────────────────────────────────────────────

STANDARD_BASIC = ResponseProfileDefinition(
    id="standard_basic",
    name="Standard – Basic",
    difficulty=Difficulty.BASIC,
    latency=LatencyConfig(min_ms=5, max_ms=80, p99_ms=200),
    error_style=ErrorStyleConfig(format="json", include_stack_trace=False, randomize_message=False),
    default_headers={
        "Content-Type": "application/json",
        "X-Powered-By": "Express",
    },
    description="Simple, sparse responses. Obvious fake, low realism.",
)

STANDARD_MEDIUM = ResponseProfileDefinition(
    id="standard_medium",
    name="Standard – Medium",
    difficulty=Difficulty.MEDIUM,
    latency=LatencyConfig(min_ms=20, max_ms=250, p99_ms=800),
    error_style=ErrorStyleConfig(format="json", include_stack_trace=False, randomize_message=True),
    default_headers={
        "Content-Type": "application/json",
        "X-Powered-By": "Express",
        "X-Request-Id": "{{uuid}}",
    },
    description="Plausible structure, moderate detail. Default for most templates.",
)

STANDARD_ADVANCED = ResponseProfileDefinition(
    id="standard_advanced",
    name="Standard – Advanced",
    difficulty=Difficulty.ADVANCED,
    latency=LatencyConfig(min_ms=30, max_ms=400, p99_ms=1200),
    error_style=ErrorStyleConfig(format="json", include_stack_trace=True, randomize_message=True),
    default_headers={
        "Content-Type": "application/json",
        "X-Powered-By": "Express",
        "X-Request-Id": "{{uuid}}",
        "X-RateLimit-Limit": "1000",
        "X-RateLimit-Remaining": "{{int:950-999}}",
    },
    description="Highly realistic responses with rich metadata. Maximises deception.",
)

# ── Specialised profiles ──────────────────────────────────────────────────────

LEGACY_MEDIUM = ResponseProfileDefinition(
    id="legacy_medium",
    name="Legacy API – Medium",
    difficulty=Difficulty.MEDIUM,
    latency=LatencyConfig(min_ms=50, max_ms=600, p99_ms=2000),
    error_style=ErrorStyleConfig(format="plain", include_stack_trace=True, randomize_message=True),
    default_headers={
        "Content-Type": "application/json",
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
    },
    description="Simulates an older, less-polished API with higher latency and plain-text errors.",
)

ERROR_TRAP_MEDIUM = ResponseProfileDefinition(
    id="error_trap_medium",
    name="Error-heavy Trap – Medium",
    difficulty=Difficulty.MEDIUM,
    latency=LatencyConfig(min_ms=10, max_ms=150, p99_ms=500),
    error_style=ErrorStyleConfig(format="json", include_stack_trace=True, randomize_message=True),
    default_headers={
        "Content-Type": "application/json",
    },
    description="Returns frequent 4xx/5xx errors with verbose messages. Induces more probing.",
)

# ── Registry helper ───────────────────────────────────────────────────────────

ALL_RESPONSE_PROFILES = [
    STANDARD_BASIC,
    STANDARD_MEDIUM,
    STANDARD_ADVANCED,
    LEGACY_MEDIUM,
    ERROR_TRAP_MEDIUM,
]
