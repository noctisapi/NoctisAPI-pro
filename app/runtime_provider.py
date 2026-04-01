"""RuntimeConfigProvider — the single source of truth for the effective runtime config.

This module is the bridge between:
  - The static catalog (app/catalog/)
  - The DB-persisted instance config (app/instance_config/ via LegacyConfigAdapter)
  - The runtime consumers (middleware, future ResponseFactory)

PUBLIC INTERFACE (what the rest of the codebase imports):
  get_runtime_config()                   → EffectiveRuntimeConfig
  resolve_effective_endpoint(meth, path) → Optional[EffectiveEndpoint]
  invalidate_runtime_cache()             → None (call after config changes)
  get_provider()                         → RuntimeConfigProvider (for testing / DI)

DESIGN DECISIONS:
  - Catalog loaded once at first access, then cached forever (immutable).
  - EffectiveRuntimeConfig cached with TTL (default 60s, env HP_RUNTIME_CACHE_TTL).
  - All errors are caught; fallback to safe default InstanceConfig on DB failure.
  - Thread-safe via threading.Lock (held < 5ms for DB reads).
  - No FastAPI dependency — safe to import from any context.

NON-GOALS:
  - Does NOT replace api_modular.resolve_request_policy(). Both coexist.
  - Does NOT modify DB tables.
  - Does NOT touch the events / actors / scoring pipeline.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from typing import Optional

from app.catalog.builtin.loader import build_default_registry
from app.catalog.registry import CatalogRegistry, CatalogValidationError
from app.instance_config.models import InstanceConfig
from app.runtime.builder import BuildError, build_effective_runtime_config
from app.runtime.models import EffectiveEndpoint, EffectiveRuntimeConfig

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_DEFAULT_DB_PATH = "/data/honeypot.db"
_DEFAULT_CACHE_TTL = 60        # seconds
_DEFAULT_BASE_TEMPLATE = "ecommerce"


def _db_path() -> str:
    return os.environ.get("HP_DB_PATH", _DEFAULT_DB_PATH)


def _cache_ttl() -> int:
    try:
        return int(os.environ.get("HP_RUNTIME_CACHE_TTL", _DEFAULT_CACHE_TTL))
    except (TypeError, ValueError):
        return _DEFAULT_CACHE_TTL


# ── RuntimeConfigProvider ────────────────────────────────────────────────────

class RuntimeConfigProvider:
    """Owns the EffectiveRuntimeConfig lifecycle.

    Lifecycle:
      1. Catalog is loaded once at __init__ time (all in-memory, no I/O).
         If catalog load fails, a CatalogValidationError is raised immediately
         (this is a programmer error, not a runtime error — fail fast).

      2. On first get_config() call (and on cache expiry), InstanceConfig is
         loaded from DB via LegacyConfigAdapter. If DB is unavailable, falls
         back to InstanceConfig.default() and logs a warning.

      3. build_effective_runtime_config() is called. If it raises BuildError,
         falls back to InstanceConfig.default() with a warning.

      4. Result is cached for _cache_ttl seconds.
    """

    def __init__(
        self,
        *,
        db_path: Optional[str] = None,
        cache_ttl_seconds: Optional[int] = None,
    ) -> None:
        self._db_path = db_path or _db_path()
        self._cache_ttl = cache_ttl_seconds if cache_ttl_seconds is not None else _cache_ttl()
        self._lock = threading.Lock()
        self._cached: Optional[EffectiveRuntimeConfig] = None
        self._cached_at: float = 0.0

        # Load catalog once. Raises CatalogValidationError on bad catalog (programmer error).
        self._registry: CatalogRegistry = build_default_registry()
        logger.debug(
            "RuntimeConfigProvider initialized: catalog=%s, ttl=%ds, db=%s",
            self._registry.summary(),
            self._cache_ttl,
            self._db_path,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def get_config(self) -> EffectiveRuntimeConfig:
        """Return current EffectiveRuntimeConfig, rebuilding if TTL expired."""
        now = time.monotonic()
        with self._lock:
            if self._cached is not None and (now - self._cached_at) < self._cache_ttl:
                return self._cached
            config = self._build_config()
            self._cached = config
            self._cached_at = now
            return config

    def invalidate(self) -> None:
        """Force cache invalidation. Next get_config() will rebuild from DB."""
        with self._lock:
            self._cached_at = 0.0
        logger.debug("RuntimeConfigProvider: cache invalidated")

    @property
    def registry(self) -> CatalogRegistry:
        """Expose the catalog registry (read-only after init)."""
        return self._registry

    # ── Private build logic ───────────────────────────────────────────────────

    def _build_config(self) -> EffectiveRuntimeConfig:
        """Build EffectiveRuntimeConfig. All errors are caught; returns safe fallback."""
        instance_config = self._load_instance_config()
        try:
            return build_effective_runtime_config(instance_config, self._registry)
        except BuildError as exc:
            logger.warning(
                "RuntimeConfigProvider: BuildError building config from DB instance config "
                "(%s); falling back to default. Error: %s",
                instance_config.base_template_id,
                exc,
            )
            try:
                return build_effective_runtime_config(
                    InstanceConfig.default(), self._registry
                )
            except BuildError as exc2:
                logger.error(
                    "RuntimeConfigProvider: BuildError even with default config: %s", exc2
                )
                raise

    def _load_instance_config(self) -> InstanceConfig:
        """Load InstanceConfig from DB via LegacyConfigAdapter.

        Falls back to InstanceConfig.default() if DB is unavailable or adapter fails.
        """
        # Import here to avoid module-level circular dependency risk.
        from app.legacy_config_adapter import LegacyConfigAdapter

        try:
            conn = sqlite3.connect(self._db_path, timeout=3)
            conn.row_factory = sqlite3.Row
            try:
                return LegacyConfigAdapter(conn, registry=self._registry).to_instance_config()
            finally:
                conn.close()
        except Exception as exc:
            logger.warning(
                "RuntimeConfigProvider: cannot load InstanceConfig from DB (%s); "
                "using default. Error: %s",
                self._db_path,
                exc,
            )
            return InstanceConfig.default()

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return provider status for diagnostic/health endpoints."""
        with self._lock:
            cached = self._cached is not None
            age = time.monotonic() - self._cached_at if cached else None
            endpoints = len(self._cached.endpoints) if self._cached else 0
            template = self._cached.template_id if self._cached else None
        return {
            "cache_populated": cached,
            "cache_age_seconds": round(age, 1) if age is not None else None,
            "cache_ttl_seconds": self._cache_ttl,
            "endpoints_loaded": endpoints,
            "template_id": template,
            "catalog": self._registry.summary(),
        }


# ── Process-level singleton ───────────────────────────────────────────────────

_provider_lock = threading.Lock()
_default_provider: Optional[RuntimeConfigProvider] = None


def get_provider() -> RuntimeConfigProvider:
    """Get or create the process-level RuntimeConfigProvider singleton.

    Uses double-checked locking. Safe to call from any thread or async context
    (the lock is only held during initial creation).

    For testing, use RuntimeConfigProvider directly to avoid global state.
    """
    global _default_provider
    if _default_provider is not None:
        return _default_provider
    with _provider_lock:
        if _default_provider is None:
            try:
                _default_provider = RuntimeConfigProvider()
            except CatalogValidationError as exc:
                logger.error(
                    "FATAL: built-in catalog is invalid — the application cannot start "
                    "correctly. Error: %s",
                    exc,
                )
                raise
    return _default_provider


def reset_provider() -> None:
    """Reset the global singleton. Intended for tests only."""
    global _default_provider
    with _provider_lock:
        _default_provider = None


# ── Public interface functions ────────────────────────────────────────────────

def get_runtime_config() -> EffectiveRuntimeConfig:
    """Return the current EffectiveRuntimeConfig from the process-level provider.

    This is the primary entry point for any code that needs the runtime config.
    Never raises (errors produce a safe fallback config).
    """
    return get_provider().get_config()


def resolve_effective_endpoint(method: str, path: str) -> Optional[EffectiveEndpoint]:
    """Resolve an HTTP (method, path) pair to its EffectiveEndpoint.

    Returns None when:
      - The path has no catalog entry (unmapped route, scanner probe, etc.)
      - The provider is not yet initialized
      - Any internal error occurs

    Never raises. Intended as a safe, always-available lookup.

    Note: This performs pattern matching (e.g. /orders/123 → /orders/{order_id}).
    See app/endpoint_resolver.py for the matching algorithm.
    """
    # Import here to avoid circular import at module level.
    from app.endpoint_resolver import EndpointResolver
    try:
        return EndpointResolver(get_provider()).resolve(method, path)
    except Exception as exc:
        logger.debug("resolve_effective_endpoint error: %s", exc)
        return None


def invalidate_runtime_cache() -> None:
    """Invalidate the runtime config cache.

    Call this after any change to api_endpoint_configs, instance_config,
    or enabled extensions. The next request will rebuild from DB.

    Safe to call even if the provider is not yet initialized.
    """
    global _default_provider
    if _default_provider is not None:
        _default_provider.invalidate()
