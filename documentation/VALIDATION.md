ShadowAPI validation checklist

1) Ensure schema applied

Run in Python REPL or sqlite3:

sqlite3 /data/honeypot.db "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"

You should see: actors, cases, campaign_actor_links, campaigns, events, session_steps, sessions, etc.

2) Create a case (HTTP)

curl -X POST "http://127.0.0.1:8080/dashboard/cases?title=TestCase&description=demo&severity=low"

Expect: {"id": <case_id>}

3) Add an actor to case

curl -X POST "http://127.0.0.1:8080/dashboard/cases/1/actors?actor_id=<actor_id>"

4) Archive actor

curl -X POST "http://127.0.0.1:8080/dashboard/actors/<actor_id>/archive"

Verify in sqlite:

sqlite3 /data/honeypot.db "SELECT actor_id,is_archived FROM actors WHERE actor_id='<actor_id>'"

5) Sessions & steps

Trigger events by calling the public API (honeypot_public) endpoints multiple times from the same client. Then:

curl "http://127.0.0.1:8080/dashboard/actors/<actor_id>/sessions"

Expect JSON with session_id, started_at, ended_at.

6) Recompute campaigns

curl -X POST "http://127.0.0.1:8080/dashboard/campaigns/recompute"

Then view campaigns:

curl "http://127.0.0.1:8080/dashboard/campaigns"

7) SQL checks

- Events retained when actor archived: ensure that purge jobs (if any) skip events tied to actors with is_archived=1.

Notes
- Endpoints use query parameters for simplicity (create case, add actor, add evidence).
- UI templates are minimal. You can extend them as needed.
