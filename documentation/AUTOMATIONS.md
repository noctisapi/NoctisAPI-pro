AUTOMATIONS (automatic behavior)

This document describes what the system does automatically in two areas:
sessions (event grouping) and campaign recompute. The source of truth is
the code in `app/honeypot_public.py` and `app/panel_mvp.py`.

Sessions: how events are grouped

1) Actor identity
- `actor_id` is computed as `sha256(ip + '|' + user-agent + '|' + HP_SEED)`.
- The actor is stable by IP + User-Agent (and seed).
- Tokens do not affect `actor_id`.

2) Session fingerprint
- To decide whether to reuse a session, the system creates a fingerprint:
  `ip|user-agent|token`.
- The token is read only from `Authorization: Bearer ...`.
- If there is no token, the fingerprint is just ip + user-agent.

3) Reuse vs new session
- The latest session for the actor with the same fingerprint is fetched.
- The `ended_at` timestamp is compared with now.
- If the gap is <= 15 minutes, that session is reused.
- Otherwise a new session is created with `session_id = secrets.token_hex(8)`.
- In both cases `ended_at` is updated to current time.

4) Points and stages inside the session
- Each event assigns points (by type) and updates actor score.
- If the session is reused, a 1.5x multiplier is applied.
- `stage_before` and `stage_after` are computed from the score.
- `stage_max` is updated when the new stage is higher.

5) Persistence
- Every request inserts a row in `events`.
- Every request inserts a `session_step` with:
  seq, timestamp, method, path, headers/query/body, status,
  stage_before and stage_after.
- If this part fails, the API does not fail (it only logs a warning).

Campaigns: how recompute works

Endpoint: `POST /dashboard/campaigns/recompute` in `app/panel_mvp.py`.

1) Scope and cleanup
- Recompute clears `campaigns` and `campaign_actor_links`.
- It only analyzes the latest N actors by `last_seen` (configurable).

2) Actor features
- For each actor, it takes up to N recent sessions (configurable).
- From session steps it extracts:
  - Normalized paths (lowercase, no querystring).
  - Path n-grams (3-grams and 2-grams), top 12.
  - Individual paths, top 10.
  - Stage flow (S0-S1-... without consecutive duplicates).
  - Stage counts (frequency per stage).
  - Timing bucket based on median step delta:
    burst (<1s), steady (<5s), slow (>=5s), unknown (no data).
  - Errors (HTTP >= 400), top 3.
- If there are no steps, it falls back to last 100 `events` paths.
- User-Agent is stored as metadata only (not used for similarity).
- Features are cached in `actor_fingerprints` and reused when:
  - cached `updated_at` >= `actors.last_seen`
  - and the same configuration is used

3) Grouping criteria
- Min features per actor: 4.
- Min intersection: 3.
- Min Jaccard: 0.4.
- Greedy clustering: pick a seed actor and add others that meet thresholds.
- Only campaigns with size >= 2 are created.

4) Output
- Inserts a campaign with summary (seed, top paths, stage flow,
  stage counts, timing, UA, representative_session_id).
- Inserts links per actor with reasons:
  shared_paths, shared_stage_flow, shared_timing, shared_errors, shared_ua.

Notes
- Configurable via env:
  - `HP_CAMPAIGN_MIN_FEATURES` (default 4)
  - `HP_CAMPAIGN_MIN_INTERSECTION` (default 3)
  - `HP_CAMPAIGN_MIN_JACCARD` (default 0.4)
  - `HP_CAMPAIGN_MAX_SESSIONS` (default 5)
  - `HP_CAMPAIGN_PATH_NGRAM_TOP_K` (default 12)
  - `HP_CAMPAIGN_PATH_TOP_K` (default 10)
  - `HP_CAMPAIGN_ACTOR_LIMIT` (default 200)
- Recompute runs as a background job and stores metrics in `campaign_jobs`.
  Status: `/dashboard/campaigns/recompute/status`.
