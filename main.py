"""Public API entrypoint.

Start with:

    python main.py

Environment variables consumed here (in addition to the application's own
env vars defined in app/):

  PORT                  TCP port to listen on (default: 8000)
  UVICORN_HOST          Bind address (default: 0.0.0.0)
  UVICORN_FORWARDED_IPS Comma-separated IPs/CIDRs whose forwarded headers
                        uvicorn itself trusts for scheme detection (default:
                        127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)
  UVICORN_ACCESS_LOG    Set to 1 to enable access logging (default: 0)
  UVICORN_RELOAD        Set to 1 to enable auto-reload (dev only)

Timeout variables (see app/server_config.py for full documentation):

  REQUEST_TIMEOUT       Per-request wall-clock limit in seconds (default: 30)
  KEEPALIVE_TIMEOUT     Keep-Alive connection idle timeout in seconds (default: 75)
  IDLE_TIMEOUT          Alias for KEEPALIVE_TIMEOUT when KEEPALIVE_TIMEOUT is
                        not set (default: 65)

Logging variables (see app/structured_logging.py for full documentation):

  LOG_LEVEL             Root log level: debug|info|warning|error (default: info)
  LOG_FORMAT            json|text — auto-detects tty when unset
  LOG_SYSLOG_HOST       Syslog/SIEM host; when set a SysLogHandler is added
  LOG_SYSLOG_PORT       Syslog port (default: 514)
  LOG_SYSLOG_SOCKTYPE   tcp|udp (default: udp)
  LOG_SYSLOG_FACILITY   Syslog facility name (default: user)
"""

from __future__ import annotations

import os

import uvicorn

from app.server_config import get_uvicorn_kwargs
from app.structured_logging import configure_logging

if __name__ == "__main__":
    # Configure structured logging before uvicorn starts so that startup
    # messages and all subsequent log records use the chosen format.
    # log_config=None prevents uvicorn from resetting the configuration.
    configure_logging()

    _truthy = ("1", "true", "yes")

    uvicorn.run(
        "app.honeypot_public:app",
        host=os.environ.get("UVICORN_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get(
            "UVICORN_FORWARDED_IPS",
            "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        ),
        access_log=os.environ.get("UVICORN_ACCESS_LOG", "0").strip().lower() in _truthy,
        reload=os.environ.get("UVICORN_RELOAD", "0").strip().lower() in _truthy,
        log_config=None,
        **get_uvicorn_kwargs(),
    )
