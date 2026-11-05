#!/usr/bin/env python
"""
Operator CLI for NoctisAPI PRO admin panel user accounts (NOC-018).

There is no self-service sign-up or invite UI yet (that's NOC-020) and no
SMTP integration for self-service password recovery -- an operator with
container/host access runs this to create accounts and issue reset links.

Run inside a container (recommended):
  docker compose exec admin python /app/scripts/panel_user.py create-user --username ops
  docker compose exec admin python /app/scripts/panel_user.py list-users
  docker compose exec admin python /app/scripts/panel_user.py reset-password --username ops
  docker compose exec admin python /app/scripts/panel_user.py deactivate-user --username ops
  docker compose exec admin python /app/scripts/panel_user.py revoke-sessions --username ops
"""
from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys

# Allow running from the repo root without needing to pre-set PYTHONPATH.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from app import panel_auth  # noqa: E402


def _db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    panel_auth.ensure_tables(conn)
    return conn


def _prompt_password() -> str:
    while True:
        password = getpass.getpass("Password (min 12 chars): ")
        if len(password) < 12:
            print("Password must be at least 12 characters.", file=sys.stderr)
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords did not match, try again.", file=sys.stderr)
            continue
        return password


def cmd_create_user(args: argparse.Namespace) -> int:
    password = args.password or _prompt_password()
    conn = _db(args.db)
    try:
        try:
            panel_auth.create_user(conn, args.username, password)
        except panel_auth.UsernameTakenError:
            print(f"Username '{args.username}' already exists.", file=sys.stderr)
            return 1
    finally:
        conn.close()
    print(f"User '{args.username}' created.")
    return 0


def cmd_list_users(args: argparse.Namespace) -> int:
    conn = _db(args.db)
    try:
        users = panel_auth.list_users(conn)
    finally:
        conn.close()
    if not users:
        print("(no users)")
        return 0
    for u in users:
        status = "active" if u["is_active"] else "deactivated"
        last_login = u["last_login_at"] or "never"
        print(f"{u['id']:>4}  {u['username']:<24} {status:<12} last_login={last_login}")
    return 0


def cmd_deactivate_user(args: argparse.Namespace) -> int:
    conn = _db(args.db)
    try:
        user = panel_auth.get_user_by_username(conn, args.username)
        if not user:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        panel_auth.set_user_active(conn, user["id"], False)
    finally:
        conn.close()
    print(f"User '{args.username}' deactivated; all sessions revoked.")
    return 0


def cmd_activate_user(args: argparse.Namespace) -> int:
    conn = _db(args.db)
    try:
        user = panel_auth.get_user_by_username(conn, args.username)
        if not user:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        panel_auth.set_user_active(conn, user["id"], True)
    finally:
        conn.close()
    print(f"User '{args.username}' re-activated.")
    return 0


def cmd_reset_password(args: argparse.Namespace) -> int:
    conn = _db(args.db)
    try:
        user = panel_auth.get_user_by_username(conn, args.username)
        if not user:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        token = panel_auth.create_password_reset(conn, user["id"])
    finally:
        conn.close()
    admin_host = os.getenv("HP_ADMIN_HOST", "<HP_ADMIN_HOST>")
    print("Share this link with the user out-of-band. Valid for 1 hour, one use only:")
    print(f"  https://{admin_host}/reset-password?token={token}")
    return 0


def cmd_revoke_sessions(args: argparse.Namespace) -> int:
    conn = _db(args.db)
    try:
        user = panel_auth.get_user_by_username(conn, args.username)
        if not user:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        panel_auth.revoke_all_sessions_for_user(conn, user["id"])
    finally:
        conn.close()
    print(f"All sessions for '{args.username}' revoked.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=os.getenv("HP_DB_PATH", "/data/honeypot.db"))
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create-user", help="Create a new panel user account")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--password", default="", help="Omit to be prompted securely")
    p_create.set_defaults(func=cmd_create_user)

    p_list = sub.add_parser("list-users", help="List panel user accounts")
    p_list.set_defaults(func=cmd_list_users)

    p_deact = sub.add_parser("deactivate-user", help="Deactivate a user and revoke all their sessions")
    p_deact.add_argument("--username", required=True)
    p_deact.set_defaults(func=cmd_deactivate_user)

    p_act = sub.add_parser("activate-user", help="Re-activate a deactivated user")
    p_act.add_argument("--username", required=True)
    p_act.set_defaults(func=cmd_activate_user)

    p_reset = sub.add_parser("reset-password", help="Issue a one-time password-reset link")
    p_reset.add_argument("--username", required=True)
    p_reset.set_defaults(func=cmd_reset_password)

    p_revoke = sub.add_parser("revoke-sessions", help="Revoke all active sessions for a user")
    p_revoke.add_argument("--username", required=True)
    p_revoke.set_defaults(func=cmd_revoke_sessions)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
