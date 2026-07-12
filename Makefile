.PHONY: up down test lint fmt

COMPOSE := docker compose -f infra/docker-compose.yml

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

test:
	cd backend && python -m pytest tests/test_infra/test_health.py -v

lint:
	cd backend && ruff check app tests && mypy app

fmt:
	cd backend && ruff check --fix app tests && ruff format app tests
