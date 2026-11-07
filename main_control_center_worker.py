"""Dedicated entrypoint for the read-only Control Center worker.

The process is disabled unless explicitly enabled. It never executes deploy,
upgrade, backup, suspend or teardown operations.
"""

from __future__ import annotations

import logging
import os
import signal
import sqlite3
from threading import Event

from control_center.repository import connect_sqlite
from control_center.runtime import WorkerRuntimeConfig, run_worker


_logger = logging.getLogger("control-center-worker")


def main() -> int:
    config = WorkerRuntimeConfig.from_env()
    if not config.enabled:
        _logger.info("Control Center worker disabled; exiting")
        return 0

    stop_event = Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda _signum, _frame: stop_event.set())

    db_path = os.getenv("HP_DB_PATH", "/data/honeypot.db")
    conn = connect_sqlite(db_path)
    try:
        conn.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
        return run_worker(conn, config=config, stop_event=stop_event)
    except sqlite3.Error as exc:
        raise RuntimeError("Control Center database schema is unavailable; run Alembic first") from exc
    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
    raise SystemExit(main())
