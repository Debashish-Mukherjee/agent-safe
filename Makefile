PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
DC ?= $(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo "docker compose")

.PHONY: setup lint test demo-openclaw demo-modeb-gateway clean

setup:
	$(PIP) install --upgrade pip
	$(PIP) install -e ./agentsafe pytest
	docker build -f agentsafe/agentsafe/sandbox/images/Dockerfile.sandbox -t agentsafe-sandbox:local .

lint:
	$(PYTHON) -m compileall -q agentsafe

test:
	pytest agentsafe/tests

demo-openclaw:
	$(DC) -f integrations/openclaw/docker-compose.yml up --build --abort-on-container-exit demo-runner
	$(DC) -f integrations/openclaw/docker-compose.yml down --remove-orphans

demo-modeb-gateway:
	$(DC) -f integrations/light_gateway/docker-compose.yml up --build --abort-on-container-exit modeb-demo-runner
	$(DC) -f integrations/light_gateway/docker-compose.yml down --remove-orphans

clean:
	rm -rf .pytest_cache agentsafe/.pytest_cache
	rm -rf audit/*.jsonl audit/*.md || true
	rm -f .agentsafe_approvals
