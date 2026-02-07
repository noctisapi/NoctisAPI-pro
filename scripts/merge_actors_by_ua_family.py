import argparse
import hashlib
import os
import sqlite3
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

def normalize_ua(ua: str) -> str:
    raw = (ua or "").strip().lower()
    if not raw:
        return "unknown"
    if "curl/" in raw:
        return "curl"
    if "python-httpx" in raw:
        return "python-httpx"
    if "python-requests" in raw:
        return "python-requests"
    if "okhttp" in raw:
        return "okhttp"
    if "go-http-client" in raw:
        return "go-http-client"
    if "java/" in raw or "jdk" in raw:
        return "java"
    if "postmanruntime" in raw:
        return "postman"
    if "wget/" in raw:
        return "wget"
    if "httpie" in raw:
        return "httpie"
    if "edge/" in raw or "edg/" in raw:
        return "edge"
    if "firefox/" in raw:
        return "firefox"
    if "chrome/" in raw and "safari/" in raw:
        return "chrome"
    if "safari/" in raw and "chrome/" not in raw:
        return "safari"
    if "mozilla/" in raw:
        return "mozilla"
    return "other"

def actor_id_from(ip: str, ua: str, seed: str) -> str:
    raw = f"{ip}|{ua}|{seed}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()

def get_tables_with_actor_id(conn: sqlite3.Connection) -> List[Tuple[str, List[str]]]:
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    out = []
    for t in tables:
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info({t})").fetchall()]
        if "actor_id" in cols:
            out.append((t, cols))
    return out

def parse_args():
    p = argparse.ArgumentParser(description="Merge actors by IP + UA family.")
    p.add_argument("--db", default="/data/honeypot.db")
    p.add_argument("--seed", default=os.getenv("HP_SEED", ""))
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    if not args.seed:
        print("ERROR: --seed or HP_SEED required", file=sys.stderr)
        return 1

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Build mapping old_actor -> new_actor based on latest event with ip+ua
    cur.execute("""
        SELECT e.actor_id, e.ip, e.ua
        FROM events e
        JOIN (
            SELECT actor_id, MAX(id) AS max_id
            FROM events
            WHERE ip IS NOT NULL AND ua IS NOT NULL AND ip != '' AND ua != ''
            GROUP BY actor_id
        ) m ON e.actor_id = m.actor_id AND e.id = m.max_id
    """)
    mapping: Dict[str, str] = {}
    for row in cur.fetchall():
        new_id = actor_id_from(row["ip"], normalize_ua(row["ua"]), args.seed)
        mapping[row["actor_id"]] = new_id

    if not mapping:
        print("No actors with ip+ua found. Nothing to merge.")
        return 0

    # Update events actor_id
    updated_events = 0
    for old_id, new_id in mapping.items():
        if old_id == new_id:
            continue
        cur.execute("UPDATE events SET actor_id=? WHERE actor_id=?", (new_id, old_id))
        updated_events += cur.rowcount

    # Update other tables with actor_id
    tables = get_tables_with_actor_id(conn)
    updated_rows = defaultdict(int)
    for table, _cols in tables:
        if table in ("events", "actors", "actor_fingerprints"):
            continue
        for old_id, new_id in mapping.items():
            if old_id == new_id:
                continue
            cur.execute(f"UPDATE {table} SET actor_id=? WHERE actor_id=?", (new_id, old_id))
            updated_rows[table] += cur.rowcount

    # Handle actor_fingerprints separately (unique PK on actor_id) by rebuilding
    fp_merged = {}
    if "actor_fingerprints" in {t for t, _ in tables}:
        cur.execute("SELECT actor_id, fp_json, updated_at FROM actor_fingerprints")
        fp_rows = [dict(r) for r in cur.fetchall()]
        for row in fp_rows:
            old_id = row.get("actor_id")
            new_id = mapping.get(old_id, old_id)
            existing = fp_merged.get(new_id)
            if not existing:
                fp_merged[new_id] = row
                fp_merged[new_id]["actor_id"] = new_id
                continue
            old_ts = row.get("updated_at") or ""
            new_ts = existing.get("updated_at") or ""
            if old_ts and (not new_ts or old_ts > new_ts):
                fp_merged[new_id] = row
                fp_merged[new_id]["actor_id"] = new_id

    # Rebuild actors table aggregated by new actor_id
    # Load all actors after updates to capture latest actor_id values
    cur.execute("SELECT * FROM actors")
    actor_rows = [dict(r) for r in cur.fetchall()]

    grouped = {}
    for a in actor_rows:
        old_id = a.get("actor_id")
        new_id = mapping.get(old_id, old_id)
        a["actor_id"] = new_id
        if new_id not in grouped:
            grouped[new_id] = []
        grouped[new_id].append(a)

    # Build merged actor rows
    merged_rows = []
    for new_id, rows in grouped.items():
        rows_sorted = sorted(rows, key=lambda r: (r.get("last_seen") or ""))
        last = rows_sorted[-1]
        merged = dict(last)
        merged["actor_id"] = new_id
        # min first_seen
        firsts = [r.get("first_seen") for r in rows if r.get("first_seen")]
        merged["first_seen"] = min(firsts) if firsts else last.get("first_seen")
        # max last_seen
        lasts = [r.get("last_seen") for r in rows if r.get("last_seen")]
        merged["last_seen"] = max(lasts) if lasts else last.get("last_seen")
        # max score and error counters
        merged["score"] = max(int(r.get("score") or 0) for r in rows)
        merged["err_total"] = max(int(r.get("err_total") or 0) for r in rows)
        merged["err_consecutive"] = max(int(r.get("err_consecutive") or 0) for r in rows)
        # last_status from most recent
        merged["last_status"] = last.get("last_status")
        merged["last_error_ts"] = max([r.get("last_error_ts") for r in rows if r.get("last_error_ts")], default=last.get("last_error_ts"))
        # lifecycle_state: keep deleted only if all deleted
        states = [r.get("lifecycle_state") for r in rows]
        merged["lifecycle_state"] = "deleted" if all(s == "deleted" for s in states if s is not None) else last.get("lifecycle_state")
        # is_archived: if any archived
        merged["is_archived"] = 1 if any(int(r.get("is_archived") or 0) for r in rows) else 0
        merged_rows.append(merged)

    if args.dry_run:
        print(f"Would update events: {updated_events}")
        for t, c in updated_rows.items():
            if c:
                print(f"Would update {t}: {c}")
        if fp_merged:
            print(f"Would merge actor_fingerprints: {len(fp_rows)} -> {len(fp_merged)}")
        print(f"Would merge actors: {len(actor_rows)} -> {len(merged_rows)}")
        conn.rollback()
        return 0

    # Replace actors table contents
    cur.execute("DELETE FROM actors")
    cols = [c[1] for c in cur.execute("PRAGMA table_info(actors)").fetchall()]
    placeholders = ",".join(["?"] * len(cols))
    for row in merged_rows:
        cur.execute(
            f"INSERT INTO actors({', '.join(cols)}) VALUES({placeholders})",
            tuple(row.get(c) for c in cols),
        )

    # Rebuild actor_fingerprints after updates
    if fp_merged:
        cur.execute("DELETE FROM actor_fingerprints")
        for row in fp_merged.values():
            cur.execute(
                "INSERT INTO actor_fingerprints(actor_id, fp_json, updated_at) VALUES(?,?,?)",
                (row.get("actor_id"), row.get("fp_json"), row.get("updated_at")),
            )

    # Deduplicate case_actors and campaign_actor_links after updates
    cur.execute("DELETE FROM case_actors WHERE rowid NOT IN (SELECT MIN(rowid) FROM case_actors GROUP BY case_id, actor_id)")
    cur.execute("DELETE FROM campaign_actor_links WHERE rowid NOT IN (SELECT MIN(rowid) FROM campaign_actor_links GROUP BY campaign_id, actor_id)")

    conn.commit()
    print(f"Updated events: {updated_events}")
    for t, c in updated_rows.items():
        if c:
            print(f"Updated {t}: {c}")
    print(f"Merged actors: {len(actor_rows)} -> {len(merged_rows)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
