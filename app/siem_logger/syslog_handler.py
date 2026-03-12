from __future__ import annotations

import socket
from datetime import datetime, timezone

# RFC5424 facility codes
_FACILITY_MAP: dict[str, int] = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
    "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
_SEVERITY_INFORMATIONAL = 6

_enabled: bool = False
_host: str = ""
_port: int = 514
_protocol: str = "udp"
_facility: int = 16  # local0


def configure(
    *,
    enabled: bool,
    host: str,
    port: int,
    protocol: str,
    facility_name: str,
) -> None:
    global _enabled, _host, _port, _protocol, _facility
    _enabled = bool(enabled)
    _host    = str(host or "").strip()
    _port    = int(port or 514)
    _protocol = str(protocol or "udp").lower().strip()
    _facility = _FACILITY_MAP.get(str(facility_name or "local0").lower(), 16)


def _build_rfc5424(json_payload: str) -> bytes:
    pri = (_facility * 8) + _SEVERITY_INFORMATIONAL
    ts  = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    # RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID STRUCTURED-DATA MSG
    msg = f"<{pri}>1 {ts} noctisapi honeypot - - - {json_payload}"
    return msg.encode("utf-8", errors="replace")


def emit(json_line: str) -> None:
    """Send RFC5424 syslog message. Non-blocking — silently drops on any failure."""
    if not _enabled or not _host:
        return
    payload = _build_rfc5424(json_line.rstrip("\n"))
    try:
        if _protocol == "tcp":
            with socket.create_connection((_host, _port), timeout=1.0) as sock:
                sock.sendall(payload + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)
                sock.sendto(payload, (_host, _port))
    except Exception:
        pass
