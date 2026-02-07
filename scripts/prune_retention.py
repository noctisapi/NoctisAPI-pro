import argparse
import os
import sqlite3
import sys
from typing import Dict, Tuple

TABLES = {
    "events": ("ts", "HP_RETENTION_EVENTS_DAYS", 30),
    "sessions": ("started_at", "HP_RETENTION_SESSIONS_DAYS", 30),
    "session_steps": ("ts", "HP_RETENTION_STEPS_DAYS", 30),
    "honeypot_checks": ("ts", "HP_RETENTION_CHECKS_DAYS", 14),
    "tokens": ("created_ts", "HP_RETENTION_TOKENS_DAYS", 90),
    "campaign_jobs": ("created_at", "HP_RETENTION_JOBS_DAYS", 30),
}

def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return bool(row)

def parse_args():
    p = argparse.ArgumentParser(description="Prune old data by retention windows.")
    p.add_argument("--db", default="/data/honeypot.db")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    enable = (os.getenv("HP_RETENTION_ENABLE", "1") or "1").strip().lower()
    if enable in ("0", "false", "no"):
        print("[skip] retention disabled via HP_RETENTION_ENABLE=0")
        return 0
    conn = sqlite3.connect(args.db)
    cur = conn.cursor()

    total_deleted = 0
    for table, (col, env_key, default_days) in TABLES.items():
        if not table_exists(conn, table):
            print(f"[skip] {table} (missing)")
            continue
        days = int(os.getenv(env_key, str(default_days)) or default_days)
        if days <= 0:
            print(f"[skip] {table} (retention disabled: {env_key}={days})")
            continue
        cutoff_expr = f"datetime('now','-{days} days')"
        count_sql = f"SELECT COUNT(*) FROM {table} WHERE {col} < {cutoff_expr}"
        cur.execute(count_sql)
        to_delete = int(cur.fetchone()[0])
        if args.dry_run:
            print(f"[dry-run] {table}: {to_delete} rows older than {days} days")
            continue
        if to_delete > 0:
            del_sql = f"DELETE FROM {table} WHERE {col} < {cutoff_expr}"
            cur.execute(del_sql)
            deleted = cur.rowcount if cur.rowcount != -1 else to_delete
            total_deleted += deleted
            print(f"[delete] {table}: {deleted} rows older than {days} days")
        else:
            print(f"[ok] {table}: 0 rows older than {days} days")

    if args.dry_run:
        conn.rollback()
        print("[dry-run] no changes applied")
    else:
        conn.commit()
        print(f"[done] total deleted: {total_deleted}")
    conn.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
