COMPOSE_DEV=docker compose -f compose/docker-compose.dev.yml
COMPOSE_PROD=docker compose -f compose/docker-compose.prod.yml --env-file .env.prod
# NOC-023: Managed variant -- an override layer on top of the same prod
# compose, not a separate stack. See compose/docker-compose.managed.yml.
COMPOSE_MANAGED=docker compose -f compose/docker-compose.prod.yml -f compose/docker-compose.managed.yml --env-file .env.prod
ALEMBIC=alembic

.PHONY: dev-up dev-logs dev-down prod-pull prod-up prod-logs upgrade verify deployer-help managed-pull managed-up managed-logs managed-down managed-upgrade managed-verify db-upgrade db-revision db-history

dev-up:
	$(COMPOSE_DEV) up -d --build

dev-logs:
	$(COMPOSE_DEV) logs -f

dev-down:
	$(COMPOSE_DEV) down

prod-pull:
	$(COMPOSE_PROD) pull

prod-up:
	$(COMPOSE_PROD) up -d

prod-logs:
	$(COMPOSE_PROD) logs -f

# NOC-029: backup -> pull -> migrate -> health-gated switch, with an
# automatic rollback (DB restore + previous image) on migration failure
# or a failed post-upgrade health check. Edit .env.prod's APP_VERSION to
# the new target first -- same as prod-pull/prod-up, but staged and safe.
upgrade:
	python scripts/upgrade.py

# NOC-030: one-shot post-install sweep -- DNS, TLS, the public app, the
# admin console (reachable AND gated), file/container permissions,
# backup configuration, and network isolation. Run once right after a
# fresh deploy, or any time on demand -- not a substitute for
# ops_monitor's ongoing cron checks.
verify:
	python scripts/verify.py

# NOC-035/NOC-036: private Managed PRO operator CLI. Deploy/status/verify and
# instance operations require customer-specific arguments; use this target to
# inspect its safe interface.
deployer-help:
	python scripts/deployer.py --help

managed-pull:
	$(COMPOSE_MANAGED) pull

managed-up:
	$(COMPOSE_MANAGED) up -d

managed-logs:
	$(COMPOSE_MANAGED) logs -f

managed-down:
	$(COMPOSE_MANAGED) down

managed-upgrade:
	python scripts/upgrade.py --managed

managed-verify:
	python scripts/verify.py --managed

db-upgrade:
	$(ALEMBIC) upgrade head

db-revision:
	$(ALEMBIC) revision -m "$(MSG)"

db-history:
	$(ALEMBIC) history --verbose
