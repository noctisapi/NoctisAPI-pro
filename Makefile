COMPOSE_DEV=docker compose -f compose/docker-compose.dev.yml
COMPOSE_PROD=docker compose -f compose/docker-compose.prod.yml --env-file .env.prod
ALEMBIC=alembic

.PHONY: dev-up dev-logs dev-down prod-pull prod-up prod-logs db-upgrade db-revision db-history

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

db-upgrade:
	$(ALEMBIC) upgrade head

db-revision:
	$(ALEMBIC) revision -m "$(MSG)"

db-history:
	$(ALEMBIC) history --verbose
