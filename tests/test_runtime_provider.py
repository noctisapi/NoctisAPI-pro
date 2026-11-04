"""Tests for RuntimeConfigProvider: loading, caching, fallback, invalidation.

Uses no real DB — the adapter is mocked or bypassed via DI.
"""
import time
import threading
import pytest

from app.catalog.builtin.loader import build_default_registry
from app.instance_config.models import InstanceConfig
from app.runtime.builder import build_effective_runtime_config
from app.runtime_provider import (
    RuntimeConfigProvider,
    get_provider,
    reset_provider,
    get_runtime_config,
    resolve_effective_endpoint,
    invalidate_runtime_cache,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

class _NoDBProvider(RuntimeConfigProvider):
    """Provider that always uses InstanceConfig.default() — no DB access."""

    def _load_instance_config(self) -> InstanceConfig:
        return InstanceConfig.default()


def _make_provider(**kwargs) -> _NoDBProvider:
    p = _NoDBProvider.__new__(_NoDBProvider)
    p._db_path = kwargs.get("db_path", "/nonexistent/path.db")
    p._cache_ttl = kwargs.get("cache_ttl_seconds", 60)
    import threading, time
    p._lock = threading.Lock()
    p._cached = None
    p._cached_at = 0.0
    from app.catalog.builtin.loader import build_default_registry
    p._registry = build_default_registry()
    return p


# ── Catalog load ──────────────────────────────────────────────────────────────

class TestCatalogLoad:
    def test_registry_loaded_on_init(self):
        p = _make_provider()
        assert p.registry is not None
        assert p.registry.summary()["endpoints"] > 0

    def test_registry_has_ecommerce_template(self):
        p = _make_provider()
        assert p.registry.get_template("ecommerce") is not None


# ── Config building ───────────────────────────────────────────────────────────

class TestConfigBuilding:
    def test_get_config_returns_effective_runtime_config(self):
        from app.runtime.models import EffectiveRuntimeConfig
        p = _make_provider()
        config = p.get_config()
        assert isinstance(config, EffectiveRuntimeConfig)

    def test_get_config_has_endpoints(self):
        p = _make_provider()
        config = p.get_config()
        assert len(config.endpoints) > 0

    def test_get_config_template_id_is_ecommerce(self):
        p = _make_provider()
        config = p.get_config()
        assert config.template_id == "ecommerce"


# ── Caching ───────────────────────────────────────────────────────────────────

class TestCaching:
    def test_second_call_returns_cached_object(self):
        p = _make_provider()
        c1 = p.get_config()
        c2 = p.get_config()
        assert c1 is c2  # same object identity

    def test_invalidate_forces_rebuild(self):
        build_count = [0]

        class _Counting(_NoDBProvider):
            def _build_config(self):
                build_count[0] += 1
                return super()._build_config()

        p = _Counting.__new__(_Counting)
        p._db_path = "/x"
        p._cache_ttl = 60
        import threading
        p._lock = threading.Lock()
        p._cached = None
        p._cached_at = 0.0
        from app.catalog.builtin.loader import build_default_registry
        p._registry = build_default_registry()

        p.get_config()
        p.get_config()
        assert build_count[0] == 1  # cached

        p.invalidate()
        p.get_config()
        assert build_count[0] == 2  # rebuilt

    def test_ttl_zero_rebuilds_every_call(self):
        build_count = [0]

        class _Counting(_NoDBProvider):
            def _build_config(self):
                build_count[0] += 1
                return super()._build_config()

        p = _Counting.__new__(_Counting)
        p._db_path = "/x"
        p._cache_ttl = 0  # always expired
        import threading
        p._lock = threading.Lock()
        p._cached = None
        p._cached_at = 0.0
        from app.catalog.builtin.loader import build_default_registry
        p._registry = build_default_registry()

        p.get_config()
        p.get_config()
        assert build_count[0] == 2

    def test_thread_safety(self):
        """Multiple threads should each get a valid config, no exceptions."""
        p = _make_provider()
        errors = []
        results = []

        def _worker():
            try:
                results.append(p.get_config())
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 10
        # All threads should get the same cached config
        assert all(r is results[0] for r in results)


# ── Fallback on DB failure ────────────────────────────────────────────────────

class TestFallback:
    def test_provider_with_bad_db_path_returns_default_config(self):
        """DB path doesn't exist → should fall back to default, not raise."""
        p = RuntimeConfigProvider(db_path="/nonexistent/db.sqlite", cache_ttl_seconds=0)
        config = p.get_config()
        assert config is not None
        assert config.template_id == "ecommerce"

    def test_status_method(self):
        p = _make_provider()
        p.get_config()
        status = p.status()
        assert status["cache_populated"] is True
        assert status["endpoints_loaded"] > 0
        assert status["template_id"] == "ecommerce"


# ── Global singleton ──────────────────────────────────────────────────────────

class TestGlobalSingleton:
    def setup_method(self):
        reset_provider()

    def teardown_method(self):
        reset_provider()

    def test_get_provider_returns_singleton(self):
        p1 = get_provider()
        p2 = get_provider()
        assert p1 is p2

    def test_reset_provider_creates_new_instance(self):
        p1 = get_provider()
        reset_provider()
        p2 = get_provider()
        assert p1 is not p2

    def test_get_runtime_config_returns_config(self):
        from app.runtime.models import EffectiveRuntimeConfig
        config = get_runtime_config()
        assert isinstance(config, EffectiveRuntimeConfig)

    def test_resolve_effective_endpoint_known_path(self):
        ep = resolve_effective_endpoint("GET", "/api/v1/orders/{order_id}")
        assert ep is not None
        assert ep.endpoint_id == "orders_get"

    def test_resolve_effective_endpoint_unknown_path(self):
        ep = resolve_effective_endpoint("GET", "/this/does/not/exist")
        assert ep is None

    def test_invalidate_runtime_cache_does_not_raise(self):
        get_provider()  # ensure initialized
        invalidate_runtime_cache()  # must not raise
