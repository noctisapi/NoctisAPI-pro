from app.catalog.builtin.loader import build_default_registry
from app.honeypot_public import app


def _route_signatures():
    signatures = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path:
            continue
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            signatures.add((method.upper(), path))
    return signatures


def test_every_catalog_endpoint_has_a_route():
    registry = build_default_registry()
    signatures = _route_signatures()
    missing = []
    for endpoint in registry.list_endpoints():
        key = (endpoint.method.value, endpoint.path_pattern)
        if key not in signatures:
            missing.append(key)
    assert missing == []
