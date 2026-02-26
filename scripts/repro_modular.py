#!/usr/bin/env python
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
from typing import Any
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import httpx
except Exception as exc:  # pragma: no cover - utility script
    raise SystemExit(f"httpx is required for this script: {exc}")

from app import api_modular


def _upsert_config(db_path: str) -> None:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        api_modular.ensure_tables(conn)
        api_modular.upsert_endpoint_config(
            conn,
            path="/v1/account",
            method="GET",
            config={
                "enabled": True,
                "response_mode": "minimal",
                "fixed_status": None,
                "richness_level": 0,
            },
        )
    finally:
        conn.close()


def _headers_ok(headers: dict[str, str]) -> tuple[bool, str]:
    match = headers.get("x-hp-modular-match", "")
    source = headers.get("x-hp-modular-policy-source", "")
    error = headers.get("x-hp-modular-error", "")
    if not match or match == "default":
        return False, f"unexpected match header: {match!r}"
    if source == "fallback":
        return False, f"policy_source=fallback error={error!r}"
    return True, ""


def _is_reduced(payload: Any) -> bool:
    if isinstance(payload, dict):
        return len(payload.keys()) <= 1 and ("status" in payload or "ok" in payload or "detail" in payload)
    return False


async def _single_check(base_url: str) -> None:
    url = f"{base_url.rstrip('/')}/v1/account"
    headers = {
        "x-hp-debug": "1",
        "x-internal-monitor": "1",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url, headers=headers)
    lower_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    ok, reason = _headers_ok(lower_headers)
    if not ok:
        raise RuntimeError(f"single request headers invalid: {reason}")
    try:
        payload = response.json()
    except Exception:
        payload = {}
    if not _is_reduced(payload):
        raise RuntimeError(f"payload not reduced as expected: {json.dumps(payload, ensure_ascii=True)}")


async def _load_check(base_url: str, total: int) -> None:
    url = f"{base_url.rstrip('/')}/v1/account"
    headers = {
        "x-hp-debug": "1",
        "x-internal-monitor": "1",
    }
    fallback_count = 0
    bad_match_count = 0
    failures = 0
    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = [client.get(url, headers=headers) for _ in range(max(1, int(total)))]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            failures += 1
            continue
        lower_headers = {str(k).lower(): str(v) for k, v in result.headers.items()}
        source = lower_headers.get("x-hp-modular-policy-source", "")
        match = lower_headers.get("x-hp-modular-match", "")
        if source == "fallback":
            fallback_count += 1
        if not match or match == "default":
            bad_match_count += 1

    print(
        json.dumps(
            {
                "requests": int(total),
                "fallback_count": int(fallback_count),
                "bad_match_count": int(bad_match_count),
                "failures": int(failures),
            },
            ensure_ascii=True,
        )
    )
    if fallback_count > 0 or failures > 0:
        raise RuntimeError("concurrency check failed (fallbacks or request errors detected)")


async def _run(args: argparse.Namespace) -> None:
    _upsert_config(args.db_path)
    await _single_check(args.base_url)
    await _load_check(args.base_url, args.concurrent)


def main() -> int:
    parser = argparse.ArgumentParser(description="Repro script for modular policy application and lock stability.")
    parser.add_argument("--base-url", default=os.getenv("HP_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--db-path", default=os.getenv("HP_DB_PATH", "/data/honeypot.db"))
    parser.add_argument("--concurrent", type=int, default=40)
    args = parser.parse_args()

    try:
        asyncio.run(_run(args))
        print("ok")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
