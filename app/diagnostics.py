"""Startup environment diagnostics.

Four checks are run once at process startup and their results are logged with
a clear ``[OK]`` / ``[WARN]`` / ``[ERROR]`` prefix.  Failures are never fatal
— the application continues regardless.

Checks
------
1. DNS resolution      — can the system resolve hostnames?
2. Outbound HTTPS      — can a TLS connection be established to a configured
                         external endpoint (first host:443 in EGRESS_REQUIRED_HOSTS)?
3. Proxy configuration — is HTTP_PROXY / HTTPS_PROXY present and reachable?
4. TLS trust store     — does the configured CA bundle load without error?

Configuration
-------------
No new env vars are introduced.  All checks share ``EGRESS_CONNECT_TIMEOUT``
(default 5 s) and reuse ``EGRESS_REQUIRED_HOSTS``, ``HTTPS_PROXY``,
``HTTP_PROXY``, ``SSL_CERT_FILE``, ``REQUESTS_CA_BUNDLE``, and
``HP_EXTRA_CERTS_DIR`` already documented in ``.env.prod.example``.

Usage
-----
    from app.diagnostics import run_diagnostics
    run_diagnostics()        # called from @app.on_event("startup")
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
from dataclasses import dataclass, field
from typing import Literal, Optional
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

DiagnosticStatus = Literal["ok", "warn", "error"]

_LOOPBACK = frozenset(("localhost", "127.0.0.1", "::1", "[::1]"))


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class DiagnosticResult:
    label: str
    status: DiagnosticStatus
    detail: str = field(default="")

    def __str__(self) -> str:
        tag = {"ok": "[OK]", "warn": "[WARN]", "error": "[ERROR]"}[self.status]
        return f"{tag} {self.label}" + (f" — {self.detail}" if self.detail else "")


def _emit(result: DiagnosticResult) -> None:
    msg = str(result)
    if result.status == "ok":
        _logger.info(msg)
    elif result.status == "warn":
        _logger.warning(msg)
    else:
        _logger.error(msg)


# ---------------------------------------------------------------------------
# Check 1: DNS resolution
# ---------------------------------------------------------------------------


def check_dns_resolution(*, timeout: float = 5.0) -> DiagnosticResult:
    """Resolve the first external hostname in ``EGRESS_REQUIRED_HOSTS``.

    Falls back to the machine's own hostname when no external targets are
    configured, which verifies that the system resolver is functional.
    """
    from app.egress import parse_egress_hosts

    hosts_raw = os.environ.get("EGRESS_REQUIRED_HOSTS", "")
    parsed = parse_egress_hosts(hosts_raw)
    target: Optional[str] = next(
        (h for h, _ in parsed if h not in _LOOPBACK), None
    )

    if target is None:
        try:
            target = socket.gethostname()
        except Exception:
            target = "localhost"

    try:
        socket.getaddrinfo(target, None)
        return DiagnosticResult("DNS resolution", "ok", f"resolved {target!r}")
    except OSError as exc:
        return DiagnosticResult(
            "DNS resolution", "error", f"failed to resolve {target!r}: {exc}"
        )


# ---------------------------------------------------------------------------
# Check 2: Outbound HTTPS
# ---------------------------------------------------------------------------


def check_outbound_https(*, timeout: float = 5.0) -> DiagnosticResult:
    """Attempt a full TLS handshake to the first ``host:443`` in ``EGRESS_REQUIRED_HOSTS``.

    Uses the configured SSL context (``get_ssl_context()``) and proxy mounts
    (``build_httpx_mounts()``), so both custom CA trust stores and egress proxies
    are exercised in a single call.

    Any HTTP response — including 4xx/5xx — is considered a success, as it
    proves that a complete TCP + TLS + HTTP round-trip is possible.
    """
    import httpx

    from app.egress import parse_egress_hosts
    from app.proxy_config import build_httpx_mounts
    from app.tls_config import get_ssl_context

    hosts_raw = os.environ.get("EGRESS_REQUIRED_HOSTS", "")
    target = next(
        ((h, p) for h, p in parse_egress_hosts(hosts_raw) if p == 443),
        None,
    )

    if target is None:
        return DiagnosticResult(
            "outbound HTTPS",
            "warn",
            "no :443 target in EGRESS_REQUIRED_HOSTS — skipping",
        )

    hostname, port = target
    url = f"https://{hostname}:{port}/"

    try:
        ssl_ctx = get_ssl_context()
    except Exception as exc:
        return DiagnosticResult(
            "outbound HTTPS", "error", f"TLS context unavailable: {exc}"
        )

    try:
        with httpx.Client(
            verify=ssl_ctx,
            mounts=build_httpx_mounts(ssl_ctx),
            timeout=timeout,
        ) as client:
            resp = client.head(url, follow_redirects=False)
        return DiagnosticResult(
            "outbound HTTPS", "ok", f"{hostname} → HTTP {resp.status_code}"
        )
    except httpx.ConnectError as exc:
        return DiagnosticResult(
            "outbound HTTPS", "error", f"connect to {hostname}:{port} failed: {exc}"
        )
    except httpx.TimeoutException:
        return DiagnosticResult(
            "outbound HTTPS", "error", f"timed out connecting to {hostname}:{port}"
        )
    except Exception as exc:
        return DiagnosticResult("outbound HTTPS", "error", str(exc))


# ---------------------------------------------------------------------------
# Check 3: Proxy configuration
# ---------------------------------------------------------------------------


def _read_proxy_env() -> Optional[str]:
    """Return the first non-empty proxy URL (case-insensitive), or None."""
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(name, "").strip()
        if val:
            return val
    return None


def check_proxy_configuration(*, timeout: float = 5.0) -> DiagnosticResult:
    """Report whether an outbound proxy is configured and reachable.

    * ``[WARN]`` when no proxy is configured — informational, not a fault.
    * ``[OK]``   when the proxy TCP endpoint is reachable.
    * ``[ERROR]``when a proxy is configured but the TCP probe fails.
    """
    proxy_url = _read_proxy_env()

    if not proxy_url:
        return DiagnosticResult("proxy", "warn", "not configured")

    try:
        parsed = urlparse(proxy_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 3128)
        if not host:
            raise ValueError(f"could not parse proxy host from {proxy_url!r}")
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return DiagnosticResult("proxy", "ok", f"reachable: {proxy_url}")
    except OSError as exc:
        return DiagnosticResult(
            "proxy", "error", f"configured ({proxy_url}) but unreachable: {exc}"
        )
    except Exception as exc:
        return DiagnosticResult(
            "proxy", "warn", f"configured ({proxy_url}), probe failed: {exc}"
        )


# ---------------------------------------------------------------------------
# Check 4: TLS trust store
# ---------------------------------------------------------------------------


def _has_custom_certs() -> bool:
    """Return True when any custom CA source env var is non-empty."""
    return any(
        (os.environ.get(v) or "").strip()
        for v in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "HP_EXTRA_CERTS_DIR")
    )


def check_tls_trust_store() -> DiagnosticResult:
    """Attempt a fresh SSL context build to validate the TLS configuration.

    A fresh build (not the cached singleton) is used so that startup always
    exercises the full loading pipeline.  The cached singleton is unaffected.
    """
    from app.tls_config import build_ssl_context

    try:
        build_ssl_context()
    except (FileNotFoundError, ssl.SSLError, OSError) as exc:
        return DiagnosticResult("TLS trust store", "error", str(exc))

    detail = "custom CA loaded" if _has_custom_certs() else "system CA only"
    return DiagnosticResult("TLS trust store", "ok", detail)


# ---------------------------------------------------------------------------
# Diagnostic runner
# ---------------------------------------------------------------------------


def run_diagnostics() -> list[DiagnosticResult]:
    """Run all four environment diagnostics.

    Never raises.  Each result is logged immediately after the check returns.
    Returns the list of results (useful for tests and introspection).
    """
    try:
        timeout = float(os.environ.get("EGRESS_CONNECT_TIMEOUT", "5"))
    except ValueError:
        timeout = 5.0

    _checks = (
        ("check_dns_resolution", lambda: check_dns_resolution(timeout=timeout)),
        ("check_outbound_https", lambda: check_outbound_https(timeout=timeout)),
        ("check_proxy_configuration", lambda: check_proxy_configuration(timeout=timeout)),
        ("check_tls_trust_store", lambda: check_tls_trust_store()),
    )

    results: list[DiagnosticResult] = []
    for name, fn in _checks:
        try:
            result = fn()
        except Exception as exc:
            result = DiagnosticResult(
                name.replace("check_", "").replace("_", " "),
                "error",
                f"check raised unexpectedly: {exc}",
            )
        _emit(result)
        results.append(result)

    return results
