PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
DC ?= $(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo "docker compose")

.PHONY: setup setup-container lint lint-container test test-container test-opa-live demo-openclaw demo-modeb-gateway normalize-openclaw-fixtures clean clean-runtime

setup:
	@if $(PYTHON) -m pip --version >/dev/null 2>&1; then \
		$(PIP) install --upgrade pip; \
		$(PIP) install -e ./agentsafe pytest; \
	else \
		echo "local pip unavailable; skipping local python install (use make test-container)"; \
	fi
	docker build -f agentsafe/agentsafe/sandbox/images/Dockerfile.sandbox -t agentsafe-sandbox:local .

setup-container:
	docker build -f agentsafe/agentsafe/sandbox/images/Dockerfile.sandbox -t agentsafe-sandbox:local .

lint:
	$(PYTHON) -m compileall -q agentsafe

lint-container:
	docker run --rm -v $(PWD):/repo -w /repo python:3.11-slim sh -lc "python3 -m compileall -q agentsafe"

test:
	pytest agentsafe/tests

test-container:
	docker run --rm -v $(PWD):/repo -w /repo python:3.11-slim sh -lc "pip install -q -e ./agentsafe pytest && pytest agentsafe/tests"

test-opa-live:
	bash agentsafe/tests/run_opa_live_test.sh

demo-openclaw:
	$(DC) -f integrations/openclaw/docker-compose.yml up --build --abort-on-container-exit demo-runner
	$(DC) -f integrations/openclaw/docker-compose.yml down --remove-orphans

demo-modeb-gateway:
	$(DC) -f integrations/light_gateway/docker-compose.yml up --build --abort-on-container-exit modeb-demo-runner
	$(DC) -f integrations/light_gateway/docker-compose.yml down --remove-orphans

normalize-openclaw-fixtures:
	$(PYTHON) integrations/openclaw/normalize_captures.py

clean:
	rm -rf .pytest_cache agentsafe/.pytest_cache
	rm -rf audit/*.jsonl audit/*.md || true
	rm -f .agentsafe_approvals

clean-runtime:
	rm -rf audit/*.jsonl audit/*.md || true
	rm -f .agentsafe_approvals
