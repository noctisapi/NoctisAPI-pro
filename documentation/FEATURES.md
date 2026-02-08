# ShadowAPI Features: Cases, Replay, Campaign

## Overview

Three new features added to the ShadowAPI dashboard for advanced attack investigation and actor correlation:

### 1) **Cases** (Investigation Dossiers)

- Cases are investigation dossiers: actors, timeline, endpoints, stages, and evidence
- Lifecycle: `open`, `monitoring`, `closed`, `false_positive`
- Intelligence: techniques observed, deterministic risk score, similarity to other cases
- UI: `/dashboard/cases` list, `/dashboard/cases/{id}` detail
- Exports: `/dashboard/cases/{id}/export.json` and `/export.md`

#### DB Schema:
- `cases`: id, title, description, severity, tags, created_at, updated_at, status, campaign_id, risk_score, techniques_json, endpoints_json, stage_flow_json
- `case_actors`: case_id, actor_id, added_at, role
- `case_evidence`: case_id, ref_type, ref_id, note, added_at, evidence_json, source_path, source_method, source_stage, source_status, actor_id

#### API:
- `POST /dashboard/cases?title=...&description=...&severity=...&status=...` -> create
- `POST /dashboard/cases/{id}/status?status=...` -> lifecycle update
- `POST /dashboard/cases/{id}/campaign?campaign_id=...` -> link to campaign
- `GET /dashboard/cases` -> list
- `GET /dashboard/cases/{id}` -> detail + actors + replay evidence + intelligence
- `POST /dashboard/cases/{id}/actors?actor_id=...&role=...` -> associate

---

### 2) **Replay** (Session-based Timeline)

- Group actor events into **sessions** based on time gaps (15 min) and fingerprints (IP+UA+token)
- Each session has ordered **steps** with request/response details
- View session timeline step-by-step in UI

#### DB Schema:
- `sessions`: session_id, actor_id, started_at, ended_at, stage_max, summary, fingerprint
- `session_steps`: id, session_id, seq, ts, method, path, query_json, headers_json, body_json, response_status, response_json, stage_before, stage_after

#### Integration:
- Automatically created on every event insert in `app/honeypot_public.py`
- Heuristic: if gap > 15 min OR fingerprint changes -> new session

#### API:
- `GET /dashboard/actors/{id}/sessions` -> list sessions
- `GET /dashboard/sessions/{session_id}` -> detail + steps

---

### 3) **Campaign** (Persistent Attack Correlation)

- Persistent attack clusters correlated over time
- Deterministic grouping by endpoint patterns, sequence, timing, and errors
- Timeline: first/last seen, activity by day/week, peaks/pauses
- Scoring: deterministic based on duration, actors, stages, and sensitive endpoints
- Relationship: a campaign can generate multiple cases; cases can link to a campaign

#### DB Schema:
- `campaigns`: campaign_id, label, created_at, first_seen_at, last_seen_at, score_det, features_summary_json
- `campaign_actor_links`: campaign_id, actor_id, confidence, reasons_json, linked_at
- `actor_fingerprints`: actor_id, fp_json, updated_at

#### Job:
- `POST /dashboard/campaigns/recompute` -> enqueue recompute (status: `/dashboard/campaigns/recompute/status`)

#### API:
- `GET /dashboard/campaigns` -> list
- `GET /dashboard/campaigns/{id}` -> detail + linked actors
- `GET /dashboard/actors/{id}/campaign` -> actor's campaign (if any)

---

## Quick Start

### 1. Build & run

```bash
docker compose build --no-cache
docker compose up -d
```

### 2. Verify schema

```bash
sqlite3 /data/honeypot.db "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```


### 3. Create a case

```bash
curl -X POST "http://127.0.0.1:8080/dashboard/cases?title=MyCase&severity=high"
```

Response: `{"id": 1}`

### 4. Archive an actor

```bash
curl -X POST "http://127.0.0.1:8080/dashboard/actors/<actor_id>/archive"
```

### 5. Add actor to case

```bash
curl -X POST "http://127.0.0.1:8080/dashboard/cases/1/actors?actor_id=<actor_id>"
```

### 6. View sessions (if any)

```bash
curl "http://127.0.0.1:8080/dashboard/actors/<actor_id>/sessions"
```

### 7. Recompute campaigns

```bash
- `POST /dashboard/campaigns/recompute` -> enqueue recompute (status: `/dashboard/campaigns/recompute/status`)
```

### 8. Browse UI

- Dashboard: http://127.0.0.1:8080/
- Cases: http://127.0.0.1:8080/dashboard/cases
- Campaigns: http://127.0.0.1:8080/dashboard/campaigns
- Actor detail: Click on an actor, see new buttons (Archive, Add to Case, Sessions)

---

## Migration Notes

- Schema is auto-migrated on startup (app/honeypot_public.py + app/panel_mvp.py)
- No schema breakage: only adds new tables and columns
- Existing queries still work (events, tokens, etc.)
- Session/steps inserted alongside events (fail-safe: exceptions don't break event insert)

---

## Design Decisions

- **Minimal UI**: Query params for simplicity (no JSON bodies in POST)
- **Fail-safe**: Sessions/campaigns logic wrapped in try-except
- **Backward compatible**: Old event queries unchanged
- **Simple clustering**: Jaccard on path/flow/timing/error features (UA only metadata)
- **Session heuristic**: 15 min gap and same fingerprint triggers reuse

---

## Future Extensions

- Add more clustering features (ASN, port distribution, timing patterns)
- Implement event purge job that respects archived actors
- Add export/forensics endpoints (PCAP-like replay)
- Implement ML-based feature extraction (entropy, protocol deviation)


