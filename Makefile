# Foundry M0: only existing Compose commands; do not hide extra infrastructure.
COMPOSE := docker compose --env-file .env -f compose.yaml

.PHONY: config preflight tls-check up down ps logs

config:
	$(COMPOSE) config --quiet

preflight:
	python3 scripts/tls_preflight.py

tls-check:
	@python3 scripts/tls_check.py

up: preflight
	$(COMPOSE) up -d --no-build --pull never

down:
	$(COMPOSE) down

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs --tail=100
