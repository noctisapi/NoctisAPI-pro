"""Egress dependency declaration — DNS and TCP connectivity checks at startup.

Every host listed in ``EGRESS_REQUIRED_HOSTS`` is DNS-resolved at startup.
When a port is specified (``host:port`` format) a TCP connection is also
attempted.  Failures are logged as WARNING but never stop the application.

Configuration (env vars)
------------------------

EGRESS_REQUIRED_HOSTS   Comma or newline separated list of ``host[:port]``
                        entries.  Bare hostname → DNS-only check.
                        ``host:port`` → DNS resolution + TCP connect.
                        (default: empty — checks disabled)

EGRESS_CONNECT_TIMEOUT  Seconds to wait for each DNS/TCP attempt.
                        (default: 5)
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Optional

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_egress_hosts(raw: str) -> list[tuple[str, Optional[int]]]:
    """Parse ``EGRESS_REQUIRED_HOSTS`` value into ``(hostname, port_or_None)`` pairs.

    Accepts comma- or newline-separated entries (or a mix of both).
    Blank entries are silently ignored.  If the port token is not a valid
    integer the entry is treated as DNS-only (port = None).
    """
    entries: list[tuple[str, Optional[int]]] = []
    for token in raw.replace(",", "\n").splitlines():
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            host, _, port_str = token.rpartition(":")
            host = host.strip()
            port_str = port_str.strip()
            try:
                port: Optional[int] = int(port_str)
            except ValueError:
                # Not a valid port — treat the whole token as a bare hostname
                host, port = token, None
        else:
            host, port = token, None
        if host:
            entries.append((host, port))
    return entries


# ---------------------------------------------------------------------------
# Single-host check
# ---------------------------------------------------------------------------


def check_host(
    hostname: str,
    port: Optional[int],
    *,
    timeout: float = 5.0,
) -> dict:
    """Resolve *hostname* and, when *port* is given, attempt a TCP connect.

    Returns a result dict::

        {
            "host":  str,          # hostname as given
            "port":  int | None,   # port as given
            "dns":   "ok" | "error",
            "tcp":   "ok" | "error" | "skipped",
            "error": str | None,   # first error message encountered
        }

    Never raises — all :exc:`OSError` are caught and recorded in the result.
    """
    result: dict = {
        "host": hostname,
        "port": port,
        "dns": "error",
        "tcp": "skipped",
        "error": None,
    }

    # DNS resolution
    try:
        addr_infos = socket.getaddrinfo(
            hostname,
            port if port is not None else 80,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        result["error"] = str(exc)
        return result

    result["dns"] = "ok"

    # Optional TCP connect — try addresses in order, stop on first success
    if port is not None:
        for family, socktype, proto, _canonname, sockaddr in addr_infos:
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                try:
                    sock.connect(sockaddr)
                    result["tcp"] = "ok"
                    return result
                finally:
                    sock.close()
            except OSError as exc:
                result["tcp"] = "error"
                result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Bulk check (called from startup hooks)
# ---------------------------------------------------------------------------


def check_egress_hosts(
    hosts_raw: Optional[str] = None,
    *,
    timeout: Optional[float] = None,
) -> list[dict]:
    """Check every host in *hosts_raw* (or ``EGRESS_REQUIRED_HOSTS``).

    * DNS failure  → ``WARNING egress: DNS resolution failed for ...``
    * TCP failure  → ``WARNING egress: TCP connect failed for ...``
    * Success      → ``INFO    egress: <host> OK (dns=ok tcp=ok|skipped)``

    Never raises.  Returns the list of result dicts (useful for testing).
    """
    if hosts_raw is None:
        hosts_raw = os.environ.get("EGRESS_REQUIRED_HOSTS", "")

    if timeout is None:
        try:
            timeout = float(os.environ.get("EGRESS_CONNECT_TIMEOUT", "5"))
        except ValueError:
            _logger.warning(
                "egress: EGRESS_CONNECT_TIMEOUT is not a valid number; using 5s default"
            )
            timeout = 5.0

    hosts = parse_egress_hosts(hosts_raw)
    if not hosts:
        return []

    results: list[dict] = []
    for hostname, port in hosts:
        result = check_host(hostname, port, timeout=timeout)
        results.append(result)

        if result["dns"] == "error":
            _logger.warning(
                "egress: DNS resolution failed for %r: %s",
                hostname,
                result["error"],
            )
        elif result["tcp"] == "error":
            _logger.warning(
                "egress: TCP connect failed for %s:%s: %s",
                hostname,
                port,
                result["error"],
            )
        else:
            _logger.info(
                "egress: %s OK (dns=%s tcp=%s)",
                hostname,
                result["dns"],
                result["tcp"],
            )

    return results
