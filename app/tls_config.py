"""Configurable TLS trust store for outbound HTTP/HTTPS requests.

Loading order (additive — all sources merged into one SSLContext):
1. System CA bundle via ``ssl.create_default_context()``
2. certifi CA bundle (installed as an httpx dependency; covers many public CAs
   that may be absent from minimal Docker images)
3. ``SSL_CERT_FILE`` env var — path to a PEM CA bundle (Python / OpenSSL convention)
4. ``REQUESTS_CA_BUNDLE`` env var — same purpose, requests-library convention;
   both may be set; they are deduped by resolved path
5. PEM/CRT/CER files in the directory named by ``HP_EXTRA_CERTS_DIR``
   (default ``/certs``) — one or more corporate root CA files

TLS certificate verification is always kept enabled.  The SSLContext built
here is cached after the first call for the lifetime of the process.
"""

from __future__ import annotations

import logging
import os
import ssl
import threading
from typing import Optional

_logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cached_ctx: Optional[ssl.SSLContext] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_env_bundles(ctx: ssl.SSLContext) -> None:
    """Load CA bundles specified in SSL_CERT_FILE / REQUESTS_CA_BUNDLE."""
    loaded: set[str] = set()
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        raw = (os.environ.get(var) or "").strip()
        if not raw:
            continue
        real = os.path.realpath(raw)
        if real in loaded:
            continue
        if not os.path.isfile(real):
            raise FileNotFoundError(
                f"CA bundle specified by {var}={raw!r} does not exist"
            )
        ctx.load_verify_locations(cafile=real)
        loaded.add(real)
        _logger.debug("tls_config: loaded CA bundle from %s=%s", var, raw)


def _load_certs_dir(ctx: ssl.SSLContext) -> None:
    """Load all .crt/.pem/.cer files from HP_EXTRA_CERTS_DIR (default /certs)."""
    certs_dir = (os.environ.get("HP_EXTRA_CERTS_DIR") or "/certs").strip()
    if not os.path.isdir(certs_dir):
        return
    for name in sorted(os.listdir(certs_dir)):
        if not name.lower().endswith((".crt", ".pem", ".cer")):
            continue
        path = os.path.join(certs_dir, name)
        try:
            ctx.load_verify_locations(cafile=path)
            _logger.debug("tls_config: loaded CA cert %s", path)
        except (ssl.SSLError, OSError) as exc:
            _logger.warning("tls_config: skipping %s — %s: %s", path, type(exc).__name__, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_ssl_context() -> ssl.SSLContext:
    """Build a fresh SSL context that merges all configured CA sources.

    This function always reads the environment and filesystem; use
    ``get_ssl_context()`` to get the cached singleton instead.

    Raises ``FileNotFoundError`` when ``SSL_CERT_FILE`` or
    ``REQUESTS_CA_BUNDLE`` points to a non-existent file.
    Raises ``ssl.SSLError`` when an env-var CA bundle is malformed.
    """
    # 1. System trust store
    ctx = ssl.create_default_context()

    # 2. certifi CA bundle — covers public CAs absent from minimal images
    try:
        import certifi  # noqa: PLC0415 — optional but always present via httpx
        ctx.load_verify_locations(cafile=certifi.where())
    except (ImportError, ssl.SSLError, OSError):
        pass

    # 3+4. Env-var bundles (SSL_CERT_FILE / REQUESTS_CA_BUNDLE)
    _load_env_bundles(ctx)

    # 5. /certs directory
    _load_certs_dir(ctx)

    return ctx


def get_ssl_context() -> ssl.SSLContext:
    """Return the process-wide SSL context, building it once on first call.

    Thread-safe.  Raises on the first call if the configuration is invalid.
    """
    global _cached_ctx
    if _cached_ctx is not None:
        return _cached_ctx
    with _lock:
        if _cached_ctx is None:
            _cached_ctx = build_ssl_context()
    return _cached_ctx
