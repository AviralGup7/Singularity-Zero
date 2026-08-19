PYTHON ?= python3
VENV ?= .venv

.PHONY: venv install test lint format run-dashboard run-pipeline security-check clean docker-build docker-run

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	. $(VENV)/bin/activate && pip install -e ".[dev]"
	cd frontend && npm install

# Full suite belongs in GitHub Actions. Locally run a single shard
# (budget ~50s), e.g. pytest tests/unit/core/test_ids.py -q
test:
	@echo "Full suite is remote-only. Examples:"
	@echo "  . $(VENV)/bin/activate && pytest tests/unit/core/test_ids.py -q"
	@echo "  cd frontend && npm run test:run"

lint: install
	. $(VENV)/bin/activate && ruff check .
	. $(VENV)/bin/activate && ruff format --check .

format: install
	. $(VENV)/bin/activate && ruff format .
	. $(VENV)/bin/activate && ruff check --fix .

run-dashboard: install
	. $(VENV)/bin/activate && uvicorn src.dashboard.fastapi.main:app --host 127.0.0.1 --port 8000

run-pipeline: install
	. $(VENV)/bin/activate && cyber-pipeline run --config configs/config.json

security-check: install
	. $(VENV)/bin/activate && pip-audit
	cd frontend && npm audit

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	rm -rf .mypy_cache .pytest_cache .ruff_cache .hypothesis
	rm -rf output/logs/* output/bandit-report.json output/lint_output.txt output/test_*.txt output/security_*.txt output/head_version.txt
	cd frontend && rm -rf node_modules dist coverage

docker-build:
	docker build -t cyber-pipeline .

docker-run:
	docker run -p 8000:8000 -e DASHBOARD_API_KEY=$${DASHBOARD_API_KEY:-$(shell openssl rand -hex 32)} cyber-pipeline
