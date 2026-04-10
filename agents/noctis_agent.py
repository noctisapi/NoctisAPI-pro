#!/usr/bin/env python3
"""
NoctisAPI Log Export Agent — Reference Implementation
=====================================================

Connects outbound to NoctisAPI's /pro/internal/log-poll endpoint and
streams honeypot events to a local JSONL file.

Features:
  - Persistent cursor across restarts (stored on disk)
  - Long-polling loop with configurable wait time
  - Exponential backoff on transient errors
  - Idempotent event processing (cursor saved only after successful write)
  - Optional deduplication via event_id

Usage:
  python noctis_agent.py --config config.json

Config file example (config.json):
  {
    "server_url":              "https://your-domain.com/pro/internal/log-poll",
    "token_url":               "https://your-domain.com/pro/internal/log-token/refresh",
    "refresh_token":           "nctx_rt_<hex>",
    "private_key_file":        "./agent_private_key.pem",
    "cursor_file":             "/var/lib/noctis-agent/cursor.json",
    "token_state_file":        "/var/lib/noctis-agent/token.json",
    "output_path":             "/var/log/noctisapi/events.jsonl",
    "poll_wait_seconds":       25,
    "max_events":              100,
    "request_timeout_seconds": 35,
    "backoff_max_seconds":     15
  }

Environment variable overrides (all optional):
  NOCTIS_REFRESH_TOKEN     - initial refresh token (preferred)
  NOCTIS_PRIVATE_KEY_FILE  - private key for decrypting encrypted payloads
  NOCTIS_TOKEN_URL         - overrides token_url
  NOCTIS_TOKEN_STATE_FILE  - overrides token_state_file
  NOCTIS_SERVER_URL        — overrides server_url
  NOCTIS_BEARER_TOKEN      — overrides bearer_token (recommended; avoids token in config file)
  NOCTIS_CURSOR_FILE       — overrides cursor_file
  NOCTIS_OUTPUT_PATH       — overrides output_path
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
import time
import urllib.error
from urllib.parse import urlsplit, urlunsplit
import urllib.request
from pathlib import Path
from typing import Optional

_logger = logging.getLogger("noctis_agent")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "server_url": "",
    "token_url": "",
    "bearer_token": "",
    "refresh_token": "",
    "private_key_file": "",
    "encryption_key_id": "",
    "cursor_file": "/var/lib/noctis-agent/cursor.json",
    "token_state_file": "/var/lib/noctis-agent/token.json",
    "output_path": "/var/log/noctisapi/events.jsonl",
    "poll_wait_seconds": 25,
    "max_events": 100,
    "request_timeout_seconds": 35,
    "backoff_max_seconds": 15,
}

# Backoff schedule in seconds (retried in order, then holds at max).
_BACKOFF_SCHEDULE = [1, 2, 5, 10, 15]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: Optional[str]) -> dict:
    """Merge defaults < config file < environment variables."""
    cfg = dict(_DEFAULTS)

    if path:
        with open(path, "r") as f:
            file_cfg = json.load(f)
        cfg.update({k: v for k, v in file_cfg.items() if k in _DEFAULTS})

    # Environment overrides — token especially should come from env, not file.
    if os.environ.get("NOCTIS_SERVER_URL"):
        cfg["server_url"] = os.environ["NOCTIS_SERVER_URL"].strip()
    if os.environ.get("NOCTIS_TOKEN_URL"):
        cfg["token_url"] = os.environ["NOCTIS_TOKEN_URL"].strip()
    if os.environ.get("NOCTIS_BEARER_TOKEN"):
        cfg["bearer_token"] = os.environ["NOCTIS_BEARER_TOKEN"].strip()
    if os.environ.get("NOCTIS_REFRESH_TOKEN"):
        cfg["refresh_token"] = os.environ["NOCTIS_REFRESH_TOKEN"].strip()
    if os.environ.get("NOCTIS_CURSOR_FILE"):
        cfg["cursor_file"] = os.environ["NOCTIS_CURSOR_FILE"].strip()
    if os.environ.get("NOCTIS_TOKEN_STATE_FILE"):
        cfg["token_state_file"] = os.environ["NOCTIS_TOKEN_STATE_FILE"].strip()
    if os.environ.get("NOCTIS_OUTPUT_PATH"):
        cfg["output_path"] = os.environ["NOCTIS_OUTPUT_PATH"].strip()
    if os.environ.get("NOCTIS_PRIVATE_KEY_FILE"):
        cfg["private_key_file"] = os.environ["NOCTIS_PRIVATE_KEY_FILE"].strip()

    return cfg


def validate_config(cfg: dict) -> None:
    if not cfg.get("server_url"):
        raise ValueError("server_url is required")
    if not cfg.get("bearer_token") and not cfg.get("refresh_token"):
        raise ValueError("refresh_token or bearer_token is required")
    if cfg.get("bearer_token") and not cfg["bearer_token"].startswith("nctx_at_"):
        _logger.warning("bearer_token does not start with 'nctx_at_' - may be invalid")


# ---------------------------------------------------------------------------
# Cursor persistence
# ---------------------------------------------------------------------------

def load_cursor(cursor_file: str) -> int:
    """Return the last persisted cursor, or 0 if none exists."""
    p = Path(cursor_file)
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text())
        return int(data.get("cursor", 0))
    except Exception as exc:
        _logger.warning("cursor load failed (%s), starting from 0", exc)
        return 0


def save_cursor(cursor_file: str, cursor: int) -> None:
    """Atomically persist *cursor* to disk."""
    p = Path(cursor_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"cursor": cursor}))
    tmp.replace(p)


def load_token_state(token_state_file: str) -> dict:
    p = Path(token_state_file)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        if isinstance(data, dict):
            return data
    except Exception as exc:
        _logger.warning("token state load failed (%s), using configured token", exc)
    return {}


def save_token_state(token_state_file: str, state: dict) -> None:
    p = Path(token_state_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(p)


# ---------------------------------------------------------------------------
# Event output
# ---------------------------------------------------------------------------

def write_events(output_path: str, events: list[dict]) -> None:
    """Append events to a JSONL file. Raises on I/O error."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# HTTP polling
# ---------------------------------------------------------------------------

def poll(
    server_url: str,
    token: str,
    cursor: int,
    max_events: int,
    wait_seconds: int,
    timeout_seconds: int,
    private_key_file: str = "",
) -> dict:
    """
    POST to /pro/internal/log-poll and return the parsed JSON body.

    Raises urllib.error.HTTPError, urllib.error.URLError, or json.JSONDecodeError
    on failure.
    """
    payload = json.dumps(
        {
            "cursor": cursor,
            "max_events": max_events,
            "wait_seconds": wait_seconds,
        }
    ).encode()

    req = urllib.request.Request(
        server_url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "noctis-agent/1.0",
        },
    )

    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read()

    body = json.loads(raw)
    return decrypt_poll_payload(body, private_key_file)


def derive_token_url(server_url: str, configured_token_url: str) -> str:
    if configured_token_url:
        return configured_token_url
    if server_url.rstrip("/").endswith("/pro/internal/log-poll"):
        return server_url.rstrip("/")[: -len("/pro/internal/log-poll")] + "/pro/internal/log-token/refresh"
    parts = urlsplit(server_url)
    return urlunsplit((parts.scheme, parts.netloc, "/pro/internal/log-token/refresh", "", ""))


def refresh_tokens(token_url: str, refresh_token: str, timeout_seconds: int) -> dict:
    payload = json.dumps({"refresh_token": refresh_token}).encode()
    req = urllib.request.Request(
        token_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "noctis-agent/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read()
    body = json.loads(raw)
    if not isinstance(body, dict) or not body.get("access_token") or not body.get("refresh_token"):
        raise ValueError("token refresh response did not include access_token and refresh_token")
    return body


def decrypt_poll_payload(body: dict, private_key_file: str) -> dict:
    if not isinstance(body, dict) or not body.get("encrypted"):
        return body
    if not private_key_file:
        raise ValueError("encrypted log-export response requires private_key_file")

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise RuntimeError("cryptography package is required to decrypt log-export payloads")

    private_pem = Path(private_key_file).read_bytes()
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("private_key_file must contain an X25519 private key")

    peer_public = X25519PublicKey.from_public_bytes(
        base64.b64decode(str(body.get("ephemeral_public_key") or ""))
    )
    salt = base64.b64decode(str(body.get("salt") or ""))
    nonce = base64.b64decode(str(body.get("nonce") or ""))
    ciphertext = base64.b64decode(str(body.get("ciphertext") or ""))
    shared_secret = private_key.exchange(peer_public)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"noctisapi-log-export-v1",
    ).derive(shared_secret)
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())


# ---------------------------------------------------------------------------
# Backoff helper
# ---------------------------------------------------------------------------

class _Backoff:
    def __init__(self, schedule: list[int], max_seconds: int):
        self._sched = schedule
        self._max = max_seconds
        self._idx = 0
        self._consecutive = 0

    def fail(self) -> None:
        self._consecutive += 1
        self._idx = min(self._idx + 1, len(self._sched) - 1)

    def success(self) -> None:
        self._consecutive = 0
        self._idx = 0

    def sleep(self) -> None:
        delay = min(self._sched[self._idx], self._max)
        _logger.info("backoff: sleeping %ds (consecutive failures: %d)", delay, self._consecutive)
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Main polling loop
# ---------------------------------------------------------------------------

_PERMANENT_ERRORS = {"cursor_expired"}


def run_agent(cfg: dict) -> None:
    server_url = cfg["server_url"]
    token_url = derive_token_url(server_url, cfg.get("token_url") or "")
    cursor_file = cfg["cursor_file"]
    token_state_file = cfg["token_state_file"]
    output_path = cfg["output_path"]
    private_key_file = str(cfg.get("private_key_file") or "")
    poll_wait = int(cfg["poll_wait_seconds"])
    max_events = int(cfg["max_events"])
    timeout = int(cfg["request_timeout_seconds"])
    backoff_max = int(cfg["backoff_max_seconds"])
    token_state = load_token_state(token_state_file)
    token = str(token_state.get("access_token") or cfg.get("bearer_token") or "")
    refresh_token = str(token_state.get("refresh_token") or cfg.get("refresh_token") or "")

    backoff = _Backoff(_BACKOFF_SCHEDULE, backoff_max)
    _logger.info("agent started — server=%s cursor_file=%s output=%s", server_url, cursor_file, output_path)

    auth_failed_count = 0

    def _refresh_access_token() -> bool:
        nonlocal token, refresh_token
        if not refresh_token:
            return False
        try:
            refreshed = refresh_tokens(token_url, refresh_token, timeout)
        except Exception as exc:
            _logger.error("token refresh failed: %s", exc)
            return False
        token = str(refreshed["access_token"])
        refresh_token = str(refreshed["refresh_token"])
        save_token_state(
            token_state_file,
            {
                "access_token": token,
                "refresh_token": refresh_token,
                "expires_in": refreshed.get("expires_in"),
                "access_token_expires_at": refreshed.get("access_token_expires_at"),
                "refresh_token_expires_at": refreshed.get("refresh_token_expires_at"),
            },
        )
        _logger.info("refreshed log-export access token")
        return True

    if refresh_token and not token:
        if not _refresh_access_token():
            raise RuntimeError("initial token refresh failed")

    while True:
        cursor = load_cursor(cursor_file)

        try:
            _logger.debug("polling cursor=%d wait=%ds", cursor, poll_wait)
            body = poll(
                server_url=server_url,
                token=token,
                cursor=cursor,
                max_events=max_events,
                wait_seconds=poll_wait,
                timeout_seconds=timeout,
                private_key_file=private_key_file,
            )
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status in (401, 403, 404):
                if refresh_token and _refresh_access_token():
                    auth_failed_count = 0
                    continue
                auth_failed_count += 1
                _logger.error(
                    "auth/access error (HTTP %d) — check bearer_token and server_url "
                    "[failure #%d]",
                    status,
                    auth_failed_count,
                )
                if auth_failed_count >= 3:
                    _logger.critical(
                        "3 consecutive auth failures — stopping agent to prevent token lockout"
                    )
                    sys.exit(1)
                # Slow backoff on auth issues; do not hammer.
                time.sleep(30)
                continue
            _logger.warning("HTTP error %d — will retry", status)
            backoff.fail()
            backoff.sleep()
            continue
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            _logger.warning("network error: %s — will retry", exc)
            backoff.fail()
            backoff.sleep()
            continue
        except json.JSONDecodeError as exc:
            _logger.warning("bad JSON response: %s — will retry", exc)
            backoff.fail()
            backoff.sleep()
            continue

        # Reset auth failure counter on any successful HTTP response.
        auth_failed_count = 0

        if not isinstance(body, dict):
            _logger.warning("unexpected response shape — will retry")
            backoff.fail()
            backoff.sleep()
            continue

        if not body.get("ok"):
            error_code = body.get("error", "unknown")
            _logger.warning("server error: %s", error_code)
            if error_code in _PERMANENT_ERRORS:
                _logger.error(
                    "cursor_expired: the agent has fallen too far behind the retention window. "
                    "Resetting cursor to 0 and re-syncing from earliest available event."
                )
                save_cursor(cursor_file, 0)
            else:
                backoff.fail()
                backoff.sleep()
            continue

        events = body.get("events") or []
        new_cursor = body.get("cursor", cursor)

        if events:
            try:
                write_events(output_path, events)
            except Exception as exc:
                _logger.error("failed to write events to %s: %s — will retry without advancing cursor", output_path, exc)
                backoff.fail()
                backoff.sleep()
                continue
            # Cursor is saved ONLY after successful write — ensures no event is silently dropped.
            save_cursor(cursor_file, new_cursor)
            _logger.info("wrote %d event(s), cursor advanced to %d", len(events), new_cursor)
        else:
            _logger.debug("no new events (cursor=%d)", cursor)

        backoff.success()
        # No explicit sleep here; the long-poll wait_seconds acts as the interval
        # when the server has no events.  When events are returned immediately we
        # loop straight back to avoid missed events during bursts.


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="NoctisAPI Log Export Agent")
    parser.add_argument("--config", "-c", default=None, help="Path to JSON config file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    cfg = load_config(args.config)
    try:
        validate_config(cfg)
    except ValueError as exc:
        _logger.critical("config error: %s", exc)
        sys.exit(1)

    try:
        run_agent(cfg)
    except KeyboardInterrupt:
        _logger.info("agent stopped by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
