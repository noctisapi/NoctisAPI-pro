"""Persistence boundary for Control Center read models.

The first implementation is SQLite because that is the current local panel
storage. The UI and API depend on this boundary rather than on SQL details,
so the Control Plane can move to its own Postgres-backed service later.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from typing import Iterator, Protocol

from .customers import list_customers
from .inventory import list_inventory
from .subscriptions import subscription_summary


class ControlCenterReadRepository(Protocol):
    def customers(self, *, customer_scope: Iterable[str] | None = None) -> list[dict[str, object]]: ...
    def inventory(self, *, customer_scope: Iterable[str] | None = None, state: str | None = None) -> list[dict[str, object]]: ...
    def subscriptions(self, *, customer_scope: Iterable[str] | None = None) -> list[dict[str, object]]: ...


class SQLiteControlCenterReadRepository:
    """Read-model repository backed by an existing SQLite connection."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._conn.row_factory = sqlite3.Row

    def customers(self, *, customer_scope: Iterable[str] | None = None) -> list[dict[str, object]]:
        return [dict(row) for row in list_customers(self._conn, customer_scope=customer_scope)]

    def inventory(self, *, customer_scope: Iterable[str] | None = None, state: str | None = None) -> list[dict[str, object]]:
        return list_inventory(self._conn, customer_scope=customer_scope, state=state)

    def subscriptions(self, *, customer_scope: Iterable[str] | None = None) -> list[dict[str, object]]:
        return subscription_summary(self._conn, customer_scope=customer_scope)


def connect_sqlite(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def open_sqlite_repository(path: str) -> Iterator[SQLiteControlCenterReadRepository]:
    conn = connect_sqlite(path)
    try:
        yield SQLiteControlCenterReadRepository(conn)
    finally:
        conn.close()
