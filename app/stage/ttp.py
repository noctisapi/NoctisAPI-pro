"""TTP classification — behavior-based MITRE ATT&CK mapping.

ALL TTP assignments must go through classify_ttp().
TTP is determined from behavioral signals aggregated across the session,
never from endpoint identity alone.

Priority: IMPACT > EXFILTRATION > COLLECTION > UNAUTHORIZED_ACCESS > DISCOVERY
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ── MITRE ATT&CK registry ─────────────────────────────────────────────────────
# Maps technique key → (tid, tactic, label).
# Technique keys are the canonical vocabulary used throughout the system.

MITRE: dict[str, tuple[str, str, str]] = {
    "discovery":           ("T1595",     "Reconnaissance",      "Active Scanning"),
    "credential_brute":    ("T1110",     "Credential Access",   "Brute Force"),
    "credential_token":    ("T1528",     "Credential Access",   "Steal Application Access Token"),
    "unauthorized_access": ("T1078",     "Initial Access",      "Valid Accounts"),
    "data_collection":     ("T1530",     "Collection",          "Data from Cloud Storage Object"),
    "bulk_exfiltration":   ("T1020",     "Exfiltration",        "Automated Exfiltration"),
    "privilege_escalation":("T1078.004", "Privilege Escalation","Valid Accounts: Cloud Accounts"),
    "destructive_action":  ("T1485",     "Impact",              "Data Destruction"),
    "code_execution":      ("T1190",     "Initial Access",      "Exploit Public-Facing Application"),
    "secret_access":       ("T1552",     "Credential Access",   "Unsecured Credentials"),
}


# ── Input context ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TTPContext:
    """Behavioral signals aggregated from a full session/case.

    Built from session_steps + events — never from a single request.
    Fields reflect what the attacker DID, not which endpoint was hit.
    Endpoint identity is available as context only and never drives TTP alone.
    """
    # Volume
    request_count: int = 0
    success_count: int = 0       # 2xx responses
    failure_count: int = 0       # 4xx/5xx responses

    # Resource traversal patterns
    distinct_resource_ids: int = 0    # max distinct parameterized IDs in any endpoint family
    sequential_pattern: bool = False  # IDs increase monotonically → automated traversal

    # Failure patterns
    repeated_failures: bool = False   # >= 3 failures on same endpoint family
    auth_failure_count: int = 0       # failures specifically on auth-like paths

    # Volume / bulk signals
    bulk_access: bool = False         # exfiltration stage reached, or high-vol success pattern

    # Method signals
    has_destructive_write: bool = False  # successful DELETE, or PUT/PATCH on privileged path

    # Highest attack stage reached in session (Stage.value string)
    max_stage: str = "recon"

    # Vulnerability types observed (from stored extra_json; frozenset for hashability)
    vulnerability_types: frozenset[str] = field(default_factory=frozenset)

    # Event-kind signals
    has_secret_access: bool = False   # admin_secrets / keys_issued / backup event kinds
    has_token_events: bool = False    # token_used / unknown_token event kinds

    # Time window in seconds (first to last request in session)
    time_window_seconds: int = 0


# ── Output ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TTPResult:
    """Behavioral TTP classification for a session/case.

    primary:   the single dominant technique key (maps into MITRE registry)
    secondary: additional technique keys with independent behavioural evidence
    reason:    specific, non-generic explanation of why this TTP was assigned
    """
    primary: str
    secondary: list[str]
    reason: str

    def all_keys(self) -> list[str]:
        return [self.primary] + list(self.secondary)


# ── Internal constants ────────────────────────────────────────────────────────

_STAGE_PRIORITY: dict[str, int] = {
    "recon": 0, "access": 1, "collection": 2, "exfiltration": 3, "impact": 4,
}

_AUTH_PATH_RE = re.compile(
    r'/auth|/login|/token|/signin|/v\d+/auth|/v\d+/login|/v\d+/token',
    re.IGNORECASE,
)

# Matches the last numeric or UUID segment of a path
_ID_SEGMENT_RE = re.compile(
    r'/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)'
)

_SECRET_PATH_RE = re.compile(
    r'/apikeys|/v\d+/keys|/internal/config|/admin.*/secret|/secrets|/keys',
    re.IGNORECASE,
)
_BACKUP_PATH_RE = re.compile(
    r'/backup|/export|/download|/api/v\d+/reports|/api/v\d+/transactions',
    re.IGNORECASE,
)
_FILE_PATH_RE = re.compile(
    r'/files/|/upload|/import|/plugins/install|/themes/upload',
    re.IGNORECASE,
)
_ADMIN_PATH_RE = re.compile(
    r'/admin|/root|/console/exec|/internal',
    re.IGNORECASE,
)

# Stage → plausible vuln types: used only as fallback when vulnerability_type
# was not stored in the event's extra_json (older events).
_PHASE_VULN_INFER: dict[str, frozenset[str]] = {
    "impact":       frozenset({"PRIV_ESC", "DESTRUCTIVE_ACTION", "COMMAND_EXECUTION"}),
    "exfiltration": frozenset({"BULK_EXFIL"}),
    "collection":   frozenset({"IDOR", "DATA_EXPOSURE"}),
    "access":       frozenset({"AUTH_BYPASS", "WEAK_AUTH"}),
    "recon":        frozenset({"ENUMERATION"}),
}

_IMPACT_VULNS      = frozenset({"PRIV_ESC", "DESTRUCTIVE_ACTION", "COMMAND_EXECUTION"})
_EXFIL_VULNS       = frozenset({"BULK_EXFIL"})
_COLLECTION_VULNS  = frozenset({"IDOR", "DATA_EXPOSURE"})
_ACCESS_VULNS      = frozenset({"AUTH_BYPASS", "WEAK_AUTH"})
_RECON_VULNS       = frozenset({"ENUMERATION"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _path_family(path: str) -> str:
    """Replace the last numeric/UUID segment with {id} to group paths by endpoint family."""
    return _ID_SEGMENT_RE.sub("/{id}", path)


def _parse_extra(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            pass
    return {}


def _row_status(row: dict) -> int:
    """Return numeric HTTP status from a step or event row."""
    return int(row.get("response_status") or row.get("status") or 0)


# ── Context builder ───────────────────────────────────────────────────────────

def build_ttp_context(steps: list[dict], events: list[dict]) -> TTPContext:
    """Aggregate behavioral signals from session data into a TTPContext.

    Arguments:
        steps:  session_steps rows — method, path, response_status, ts
        events: events rows — kind, path, method, status, extra_json, ts
    """
    request_count = len(steps) + len(events)
    success_count = failure_count = 0
    auth_failures = 0
    bulk_access = False
    has_destructive_write = False
    has_secret_access = False
    has_token_events = False
    max_stage_priority = 0
    max_stage = "recon"
    vuln_types: set[str] = set()

    # endpoint family → list of resource ID strings (for traversal analysis)
    id_groups: dict[str, list[str]] = defaultdict(list)
    # endpoint family → failure count (for repeated_failures signal)
    family_failures: dict[str, int] = defaultdict(int)
    all_ts: list[str] = []

    # --- session_steps ---
    for row in steps:
        status = _row_status(row)
        path   = str(row.get("path") or "/")
        method = str(row.get("method") or "").upper()
        if row.get("ts"):
            all_ts.append(str(row["ts"]))

        if 200 <= status < 300:
            success_count += 1
            if method == "DELETE":
                has_destructive_write = True
        elif status >= 400:
            failure_count += 1
            family_failures[_path_family(path)] += 1
            if _AUTH_PATH_RE.search(path):
                auth_failures += 1

        m = _ID_SEGMENT_RE.search(path)
        if m:
            id_groups[_path_family(path)].append(m.group(1))

    # --- events ---
    for row in events:
        status = _row_status(row)
        path   = str(row.get("path") or "/")
        method = str(row.get("method") or "").upper()
        kind   = str(row.get("kind") or "")
        if row.get("ts"):
            all_ts.append(str(row["ts"]))

        if 200 <= status < 300:
            success_count += 1
        elif status >= 400:
            failure_count += 1
            family_failures[_path_family(path)] += 1
            if _AUTH_PATH_RE.search(path):
                auth_failures += 1

        extra = _parse_extra(row.get("extra_json"))
        phase = str(extra.get("attack_phase") or "recon").lower()
        prio  = _STAGE_PRIORITY.get(phase, 0)
        if prio > max_stage_priority:
            max_stage_priority = prio
            max_stage = phase

        if phase == "exfiltration":
            bulk_access = True

        # Prefer explicitly stored vulnerability_type; fall back to stage inference
        vt = extra.get("vulnerability_type")
        if vt:
            vuln_types.add(str(vt).upper())
        else:
            vuln_types.update(_PHASE_VULN_INFER.get(phase, frozenset()))

        if kind in ("admin_secrets", "keys_issued", "backup_download", "backup_list"):
            has_secret_access = True
        if kind in ("token_used", "unknown_token"):
            has_token_events = True
        if method in ("DELETE", "PUT", "PATCH") and 200 <= status < 300:
            has_destructive_write = True

        m = _ID_SEGMENT_RE.search(path)
        if m:
            id_groups[_path_family(path)].append(m.group(1))

    # --- Compute traversal signals ---
    distinct_resource_ids = 0
    sequential_pattern = False
    for ids in id_groups.values():
        distinct = len(set(ids))
        if distinct > distinct_resource_ids:
            distinct_resource_ids = distinct
        if distinct >= 2:
            numeric = sorted({int(i) for i in ids if i.isdigit()})
            if len(numeric) >= 2:
                diffs = [numeric[j + 1] - numeric[j] for j in range(len(numeric) - 1)]
                # Increasing gaps of <= 200 → automated sequential traversal
                if all(1 <= d <= 200 for d in diffs):
                    sequential_pattern = True

    repeated_failures = any(v >= 3 for v in family_failures.values())

    # Infer bulk_access also from high-volume success with wide resource spread
    if success_count >= 10 and distinct_resource_ids >= 5:
        bulk_access = True

    # --- Time window ---
    time_window_seconds = 0
    if len(all_ts) >= 2:
        parsed = _parse_timestamps(all_ts)
        if len(parsed) >= 2:
            parsed.sort()
            time_window_seconds = int((parsed[-1] - parsed[0]).total_seconds())

    return TTPContext(
        request_count=request_count,
        success_count=success_count,
        failure_count=failure_count,
        distinct_resource_ids=distinct_resource_ids,
        sequential_pattern=sequential_pattern,
        repeated_failures=repeated_failures,
        auth_failure_count=auth_failures,
        bulk_access=bulk_access,
        has_destructive_write=has_destructive_write,
        has_secret_access=has_secret_access,
        has_token_events=has_token_events,
        max_stage=max_stage,
        vulnerability_types=frozenset(vuln_types),
        time_window_seconds=time_window_seconds,
    )


def _parse_timestamps(raw: list[str]) -> list:
    from datetime import datetime
    out = []
    for s in raw:
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                out.append(datetime.strptime(s[:26], fmt))
                break
            except Exception:
                pass
    return out


# ── Classifier ────────────────────────────────────────────────────────────────

def classify_ttp(ctx: TTPContext) -> TTPResult:
    """Classify the dominant TTP for a session/case.

    Rules are evaluated in strict priority order; the first matching rule wins.
    Endpoint identity never drives TTP alone — all rules require behavioral signals.

    Priority: IMPACT > EXFILTRATION > COLLECTION > UNAUTHORIZED_ACCESS > DISCOVERY

    Returns a TTPResult with one primary, optional secondaries, and a specific reason.
    Never raises; falls back to DISCOVERY on unexpected input.
    """
    try:
        vuln  = ctx.vulnerability_types
        stage = ctx.max_stage
        secondary: list[str] = []

        # ── Secondary signals collected independently of primary ───────────────
        # These have their own clear evidence and never overlap with primary.
        if ctx.auth_failure_count >= 3:
            secondary.append("credential_brute")
        if ctx.has_token_events:
            secondary.append("credential_token")
        # secret_access only as secondary when not already captured by the primary
        _secret_secondary_eligible = stage not in ("exfiltration", "impact")

        # ── Priority 1: IMPACT ────────────────────────────────────────────────
        if stage == "impact" or ctx.has_destructive_write or (vuln & _IMPACT_VULNS):
            if "COMMAND_EXECUTION" in vuln:
                primary = "code_execution"
                reason = (
                    f"Successful upload/execution request on COMMAND_EXECUTION endpoint "
                    f"({ctx.success_count} successful request"
                    f"{'s' if ctx.success_count != 1 else ''}) → remote code execution"
                )
            elif "PRIV_ESC" in vuln or stage == "impact":
                primary = "privilege_escalation"
                reason = (
                    f"Access to privileged resource confirmed (stage reached: {stage}, "
                    f"vuln: PRIV_ESC, {ctx.success_count} successful request"
                    f"{'s' if ctx.success_count != 1 else ''}) → privilege escalation"
                )
            else:
                primary = "destructive_action"
                reason = (
                    "Successful destructive write (DELETE/PUT/PATCH on privileged endpoint) "
                    f"→ data destruction or unauthorized modification"
                )
            if ctx.distinct_resource_ids > 1 and "data_collection" not in secondary:
                secondary.append("data_collection")
            if ctx.has_secret_access and "secret_access" not in secondary:
                secondary.append("secret_access")
            return TTPResult(primary=primary, secondary=secondary, reason=reason)

        # ── Priority 2: EXFILTRATION ──────────────────────────────────────────
        if stage == "exfiltration" or ctx.bulk_access or (vuln & _EXFIL_VULNS):
            if ctx.sequential_pattern and ctx.distinct_resource_ids > 1:
                reason = (
                    f"Sequential traversal of {ctx.distinct_resource_ids} distinct resource IDs "
                    f"with {ctx.success_count} successful response"
                    f"{'s' if ctx.success_count != 1 else ''} → bulk data exfiltration"
                )
            elif ctx.bulk_access:
                extra = (
                    f" across {ctx.distinct_resource_ids} resources"
                    if ctx.distinct_resource_ids > 1 else ""
                )
                reason = (
                    f"High-volume access: {ctx.success_count} successful request"
                    f"{'s' if ctx.success_count != 1 else ''}{extra} "
                    f"in {ctx.time_window_seconds}s → automated exfiltration"
                )
            else:
                reason = (
                    f"BULK_EXFIL endpoint triggered with {ctx.success_count} successful "
                    f"request{'s' if ctx.success_count != 1 else ''} → mass data extraction"
                )
            if ctx.distinct_resource_ids > 1 and "data_collection" not in secondary:
                secondary.append("data_collection")
            if ctx.has_secret_access and _secret_secondary_eligible and "secret_access" not in secondary:
                secondary.append("secret_access")
            return TTPResult(primary="bulk_exfiltration", secondary=secondary, reason=reason)

        # ── Priority 3: COLLECTION ────────────────────────────────────────────
        if (
            (stage == "collection" or (vuln & _COLLECTION_VULNS))
            and ctx.success_count > 0
            and ctx.distinct_resource_ids > 1
        ):
            if ctx.sequential_pattern:
                reason = (
                    f"Sequential IDOR access across {ctx.distinct_resource_ids} distinct resource IDs "
                    f"({ctx.success_count} successful request"
                    f"{'s' if ctx.success_count != 1 else ''}) → systematic data collection"
                )
            else:
                reason = (
                    f"IDOR/DATA_EXPOSURE access to {ctx.distinct_resource_ids} distinct resources "
                    f"({ctx.success_count} successful request"
                    f"{'s' if ctx.success_count != 1 else ''}) → data collection"
                )
            if ctx.has_secret_access and _secret_secondary_eligible and "secret_access" not in secondary:
                secondary.append("secret_access")
            return TTPResult(primary="data_collection", secondary=secondary, reason=reason)

        # ── Priority 4: UNAUTHORIZED ACCESS ───────────────────────────────────
        if (
            (stage == "access" or (vuln & (_ACCESS_VULNS | _COLLECTION_VULNS)))
            and ctx.success_count > 0
        ):
            if vuln & _COLLECTION_VULNS:
                reason = (
                    f"Unauthorized access to protected resource via IDOR/DATA_EXPOSURE "
                    f"(single resource, {ctx.success_count} successful request"
                    f"{'s' if ctx.success_count != 1 else ''}) → unauthorized data access"
                )
            else:
                matched = ", ".join(sorted(vuln & _ACCESS_VULNS)) or "AUTH_BYPASS"
                reason = (
                    f"Authentication bypass or weak-auth exploitation ({matched}) "
                    f"with {ctx.success_count} successful access → initial unauthorized access"
                )
            if ctx.has_secret_access and _secret_secondary_eligible and "secret_access" not in secondary:
                secondary.append("secret_access")
            return TTPResult(primary="unauthorized_access", secondary=secondary, reason=reason)

        # ── Priority 5: DISCOVERY (default) ───────────────────────────────────
        if ctx.has_secret_access and _secret_secondary_eligible and "secret_access" not in secondary:
            secondary.append("secret_access")

        if ctx.repeated_failures:
            reason = (
                f"Repeated failures ({ctx.failure_count} total across same endpoint families) "
                "→ active reconnaissance / API probing"
            )
        elif vuln & _RECON_VULNS:
            reason = (
                f"ENUMERATION endpoint accessed ({ctx.request_count} request"
                f"{'s' if ctx.request_count != 1 else ''}, "
                f"{ctx.failure_count} failure"
                f"{'s' if ctx.failure_count != 1 else ''}) → API surface discovery"
            )
        else:
            reason = (
                f"Probe activity: {ctx.request_count} request"
                f"{'s' if ctx.request_count != 1 else ''}, "
                f"{ctx.failure_count} failure"
                f"{'s' if ctx.failure_count != 1 else ''} → reconnaissance"
            )

        return TTPResult(primary="discovery", secondary=secondary, reason=reason)

    except Exception as exc:  # pragma: no cover
        return TTPResult(
            primary="discovery",
            secondary=[],
            reason=f"classifier error ({exc}) → fallback to discovery",
        )


# ── Evidence collection (display only) ───────────────────────────────────────
# Evidence is collected AFTER classification, for UI display only.
# It does NOT drive TTP assignment.

_EVIDENCE_MATCHERS: dict[str, object] = {
    "discovery":           lambda r: _row_status(r) >= 400,
    "credential_brute":    lambda r: (
        bool(_AUTH_PATH_RE.search(str(r.get("path") or "")))
        and _row_status(r) in (401, 403)
    ),
    "credential_token":    lambda r: (
        str(r.get("kind") or "") in ("token_used", "unknown_token")
        or bool(_SECRET_PATH_RE.search(str(r.get("path") or "")))
    ),
    "unauthorized_access": lambda r: (
        200 <= _row_status(r) < 300
        and bool(_ID_SEGMENT_RE.search(str(r.get("path") or "")))
    ),
    "data_collection":     lambda r: (
        200 <= _row_status(r) < 300
        and bool(_ID_SEGMENT_RE.search(str(r.get("path") or "")))
    ),
    "bulk_exfiltration":   lambda r: (
        200 <= _row_status(r) < 300
        and (
            bool(_BACKUP_PATH_RE.search(str(r.get("path") or "")))
            or str(r.get("kind") or "") in ("backup_download", "backup_list")
        )
    ),
    "privilege_escalation":lambda r: (
        bool(_ADMIN_PATH_RE.search(str(r.get("path") or "")))
        and 200 <= _row_status(r) < 300
    ),
    "destructive_action":  lambda r: (
        str(r.get("method") or "").upper() in ("DELETE", "PUT", "PATCH")
        and 200 <= _row_status(r) < 300
    ),
    "code_execution":      lambda r: (
        bool(_FILE_PATH_RE.search(str(r.get("path") or "")))
        and 200 <= _row_status(r) < 300
    ),
    "secret_access":       lambda r: (
        bool(_SECRET_PATH_RE.search(str(r.get("path") or "")))
        or str(r.get("kind") or "") in ("admin_secrets", "keys_issued")
    ),
}


def _geo_from_row(row: dict) -> tuple[str, str]:
    """Return (flag_emoji, country_name) from a step or event row.

    Steps store geo in geo_json column: {"country_iso2","country_name","flag"}.
    Events store geo in extra_json under the "geo" key.
    """
    # Step: geo_json column
    geo_raw = row.get("geo_json")
    if geo_raw:
        try:
            geo = json.loads(geo_raw) if isinstance(geo_raw, str) else geo_raw
            if isinstance(geo, dict):
                return geo.get("flag") or "", geo.get("country_name") or ""
        except Exception:
            pass
    # Event: extra_json → geo
    extra_raw = row.get("extra_json")
    if extra_raw:
        try:
            extra = _parse_extra(extra_raw)
            geo = extra.get("geo") or {}
            if isinstance(geo, dict):
                iso2 = geo.get("country_iso2") or ""
                flag = geo.get("flag") or ""
                if not flag and iso2 and len(iso2) == 2:
                    flag = "".join(
                        chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2.upper()
                    )
                return flag, geo.get("country_name") or ""
        except Exception:
            pass
    return "", ""


def _collect_evidence(key: str, steps: list[dict], events: list[dict], max_rows: int = 6) -> list[dict]:
    """Return up to max_rows matching requests as evidence for a technique key.

    Evidence is for display only — it never drives TTP classification.
    Each row includes geo_flag and geo_name for flag rendering in the UI.
    """
    matcher = _EVIDENCE_MATCHERS.get(key)
    if matcher is None:
        return []

    results: list[dict] = []
    all_rows = list(steps) + list(events)
    for row in all_rows:
        if len(results) >= max_rows:
            break
        try:
            if matcher(row):
                geo_flag, geo_name = _geo_from_row(row)
                results.append({
                    "method":   str(row.get("method") or "—").upper(),
                    "path":     str(row.get("path") or "—"),
                    "status":   str(_row_status(row) or "—"),
                    "ip":       str(row.get("ip") or ""),
                    "geo_flag": geo_flag,
                    "geo_name": geo_name,
                    "ts":       str(row.get("ts") or ""),
                    "kind":     str(row.get("kind") or ""),
                })
        except Exception:
            pass
    return results


# ── Display data builder ──────────────────────────────────────────────────────

def ttp_display_data(steps: list[dict], events: list[dict]) -> dict:
    """Build the complete TTP display structure for template rendering.

    Returns a dict with:
        techniques: list[str]  — technique keys (backward-compatible with scoring)
        primary:    str        — primary technique key
        display:    list[dict] — full per-technique data for MITRE ATT&CK section
    """
    ctx    = build_ttp_context(steps, events)
    result = classify_ttp(ctx)

    keys = result.all_keys()
    display: list[dict] = []
    for i, key in enumerate(keys):
        if key not in MITRE:
            continue
        tid, tactic, label = MITRE[key]
        evidence = _collect_evidence(key, steps, events)
        secondary_label = f"Secondary indicator: {label} ({tid})"
        display.append({
            "key":      key,
            "primary":  i == 0,
            "tid":      tid,
            "tactic":   tactic,
            "label":    label,
            "reason":   result.reason if i == 0 else secondary_label,
            "evidence": evidence,
        })

    return {
        "techniques": keys,   # list[str] kept for _case_risk_score compat
        "primary":    result.primary,
        "display":    display,
    }
