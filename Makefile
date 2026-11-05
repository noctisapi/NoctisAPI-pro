COMPOSE_DEV=docker compose -f compose/docker-compose.dev.yml
COMPOSE_PROD=docker compose -f compose/docker-compose.prod.yml --env-file .env.prod
# NOC-023: Managed variant -- an override layer on top of the same prod
# compose, not a separate stack. See compose/docker-compose.managed.yml.
COMPOSE_MANAGED=docker compose -f compose/docker-compose.prod.yml -f compose/docker-compose.managed.yml --env-file .env.prod
ALEMBIC=alembic

.PHONY: dev-up dev-logs dev-down prod-pull prod-up prod-logs managed-pull managed-up managed-logs managed-down db-upgrade db-revision db-history

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

managed-pull:
	$(COMPOSE_MANAGED) pull

managed-up:
	$(COMPOSE_MANAGED) up -d

managed-logs:
	$(COMPOSE_MANAGED) logs -f

managed-down:
	$(COMPOSE_MANAGED) down

db-upgrade:
	$(ALEMBIC) upgrade head

db-revision:
	$(ALEMBIC) revision -m "$(MSG)"

db-history:
	$(ALEMBIC) history --verbose
