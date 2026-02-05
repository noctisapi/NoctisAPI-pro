Quick usage

- Build and run (docker-compose):

```bash
docker compose build --no-cache
docker compose up -d
```

- Open panel (SSH tunnel or local): http://127.0.0.1:8080/

Cases
- Create a case:
  curl -X POST "http://127.0.0.1:8080/dashboard/cases?title=Case1&description=demo"
- Add actor to case:
  curl -X POST "http://127.0.0.1:8080/dashboard/cases/1/actors?actor_id=<actor_id>"

Sessions
- View sessions for actor:
  curl "http://127.0.0.1:8080/dashboard/actors/<actor_id>/sessions"
- Open session UI at:
  http://127.0.0.1:8080/dashboard/sessions/<session_id>

Campaigns
- Run recompute (manual):
  curl -X POST "http://127.0.0.1:8080/dashboard/campaigns/recompute"
- View campaigns UI:
  http://127.0.0.1:8080/dashboard/campaigns

Validation steps are in documentation/VALIDATION.md
