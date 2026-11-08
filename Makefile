# Native foreground startup and the separate advanced Compose workflow.
COMPOSE := docker compose --env-file .env -f compose.yaml

.PHONY: start runtime-check config preflight tls-check up down ps logs local-tls-init local-tls-up

export TLS_DEST LOCAL_TLS_PROJECT LOCAL_TLS_ADOPT_PROJECT FOUNDRY_MI_DIR FOUNDRY_MI_SHA256 FOUNDRY_MI_IMAGE_ID
export FOUNDRY_SR_CHECKOUT

start:
	@python3 scripts/local_runtime.py

runtime-check:
	@python3 scripts/local_runtime.py --check

local-tls-init:
	@python3 scripts/local_tls_init.py

local-tls-up:
	@python3 scripts/local_tls_up.py

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
