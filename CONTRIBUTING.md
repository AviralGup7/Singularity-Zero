# Contributing to the Cyber Security Test Pipeline

Thanks for taking the time to contribute. This document covers the
workflow, code style, and review expectations for the project.

---

## Development setup

```bash
# 1. Clone and enter the project
git clone <repo-url> cyber-pipeline
cd cyber-pipeline

# 2. Create a virtual environment (Python 3.14 or newer required)
python3.14 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1

# 3. Install dev dependencies
pip install -e ".[dev]"

# 4. Install frontend dependencies (for the React dashboard)
cd frontend && npm install && cd ..

# 5. Sanity-check your environment
make lint           # or: ruff check .
make typecheck      # or: mypy src tests
make test           # or: pytest tests/unit -q
```

The repository ships a `Makefile` and a `pyproject.toml` configured for
`ruff` (lint + format), `mypy` (strict-ish), and `pytest`.  Pre-commit
hooks are configured in `.pre-commit-config.yaml`; install them with
`pre-commit install` after step 3.

## Code style

* **Python 3.14 baseline** � use modern type hints (`list[str]`,
  `dict[str, int]`, `T | None`) and `from __future__ import annotations`
  is no longer required.  Imports are sorted with `isort` (via ruff).
* **Formatting** — `ruff format` is the source of truth.  Do not
  hand-format; let the tool rewrite your file.
* **Line length** — 100 characters, hard cap.
* **Type annotations** — every public function should have parameter
  and return annotations.  `beartype` is installed in dev and will
  enforce type correctness at runtime for opted-in modules.
* **Logging** — use `loguru` (via `src.core.logging.get_pipeline_logger`)
  for backend modules; the standard `logging` module is fine for
  leaf libraries.
* **Tests** — every new public function gets at least one unit test.
  The coverage gate is currently 25 % at the project level, with 5 %
  per module.  New modules should aim for **≥ 80 % line coverage**; the
  gate will be raised over time.

## Pull request workflow

1. **Branch from `main`**.  Use a descriptive name with a category prefix:
   - `fix/redis-timeout-drift` — bug fixes
   - `feat/sso-oidc` — new features
   - `docs/contributing` — documentation
   - `security/csrf-hardening` — security improvements
   - `refactor/cleanup-middleware` — refactoring
   - `test/csrf-middleware` — test additions
2. **Make focused commits** — one logical change per commit. Write clear commit messages following [Conventional Commits](https://www.conventionalcommits.org/).
3. **Run the full lint + test + typecheck pipeline locally** before
   pushing:
   ```bash
   ruff check .
   ruff format --check .
   mypy src tests
   pytest tests/unit -q --tb=short
   ```
4. **Write a clear PR description** — link the issue, describe *why*
   the change is needed, and call out any new configuration knobs.
5. **Be patient with review** — security-sensitive code gets at least
   two reviewers.
6. **CI requirements** — all CI checks must pass before merge. PRs to
   `main` require at least one approval. Direct pushes to `main` are
   not permitted; all changes go through PRs.

## Adding a new detector / active probe

* The pipeline auto-discovers modules in `src/analysis/active/` and
  `src/analysis/passive/`.  Adding a new file in those directories
  with a `register()` call is enough for it to appear in the dashboard
  registry.
* Every new module must export a typed result Pydantic model from
  `src/core/models/findings.py`.
* Add at least one fixture under `tests/fixtures/security_patterns/`
  and one regression test under `tests/unit/analysis/`.

## Adding a new recon provider

* Implement `collect_for_hosts(hosts, timeout_seconds, per_host_limit,
  max_workers, progress_callback) -> tuple[set[str], dict[str, Any]]`
  in a new file under `src/recon/collectors/providers/<archive|external>/`.
* Register the tool flag in `src/recon/collectors/provider_selection.py`
  so both the blocking aggregator and the streaming aggregator pick it
  up automatically.

## Security

* Never commit secrets, API keys, or production data.  The
  `detect-secrets` baseline is checked in CI.
* Found a vulnerability in the platform itself?  Email
  `security@<project-domain>` (see `SECURITY.md`) — do not open a
  public issue.
* This tool is intended for **authorized security testing only**.
  Adding features that facilitate unauthorized access is out of scope.

## License

By contributing, you agree that your contributions are licensed under
the same terms as the project (see `LICENSE`).
