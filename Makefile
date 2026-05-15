PYTHON ?= python3
VENV ?= .venv

.PHONY: venv install test lint format run-dashboard run-pipeline

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	. $(VENV)/bin/activate && pip install -e .[dev]

test: install
	. $(VENV)/bin/activate && pytest -q

lint: install
	. $(VENV)/bin/activate && ruff check .

format: install
	. $(VENV)/bin/activate && ruff format .

run-dashboard: install
	. $(VENV)/bin/activate && cyber-dashboard --port 8000

run-pipeline: install
	. $(VENV)/bin/activate && cyber-pipeline --config configs/config.example.json --scope configs/scope.example.txt
.PHONY: install test lint format security-check clean docker-build docker-run

install:
	pip install -e ".[dev]"
	cd frontend && npm install

test:
	pytest tests/unit -v
	cd frontend && npm test

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check --fix .

security-check:
	pip-audit
	cd frontend && npm audit

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .mypy_cache .pytest_cache .ruff_cache .hypothesis
	rm -rf output/*
	cd frontend && rm -rf node_modules dist coverage

docker-build:
	docker build -t cyber-pipeline .

docker-run:
	docker run -p 8080:8080 -e DASHBOARD_API_KEY=$${DASHBOARD_API_KEY:-$(shell openssl rand -hex 32)} cyber-pipeline
