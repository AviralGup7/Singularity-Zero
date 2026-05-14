# Project Improvement Plan – Cyber Security Test Pipeline

## Investigation Summary

Comprehensive audit of the entire repository across Python source (src/), frontend, Docker, CI/CD (GitHub Actions), infrastructure configs, documentation, and tooling.

---

## CRITICAL – Security & Secrets

### 1. `.env` file tracked in repo (potential secret exposure)
- **File**: `.env`
- **Problem**: `.env` contains `APP_SECRET_KEY=REPLACE_WITH_SECURE_RANDOM_STRING` and multiple `REPLACE_WITH_*` placeholder values. While these are placeholders, having a populated `.env` file committed creates risk that users accidentally add real secrets and push. Currently `.gitignore` correctly excludes `.env` (line 53), but worth auditing that it is truly not tracked.
- **Fix**: Verify `git status` shows `.env` as untracked. Add a pre-commit hook to reject `.env` commits. Document that `.env` must never be committed.

### 2. `docker-compose.optimized.yml` has weak fallback for `APP_SECRET_KEY`
- **File**: `docker-compose.optimized.yml:8`
- **Problem**: `APP_SECRET_KEY: ${APP_SECRET_KEY:-change-me-in-production}` ships with a weak default if the env var is unset. This is dangerous for production deployments.
- **Fix**: Remove the default fallback; make it mandatory:
  ```yaml
  APP_SECRET_KEY: ${APP_SECRET_KEY:?APP_SECRET_KEY is required}
  ```

### 3. `docker-compose.yml` (dev) also has weak fallback for `APP_SECRET_KEY`
- **File**: `docker-compose.yml:56`
- **Problem**: Same pattern in dev compose.
- **Fix**: Remove default or use mandatory syntax in production compose; document dev defaults.

### 4. Grafana ships with `admin/admin` default credentials
- **File**: `docker-compose.optimized.yml:262-263`
- **Problem**: `GF_SECURITY_ADMIN_USER: ${GRAFANA_ADMIN_USER:-admin}` / `GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD:-admin}` — if env vars are unset, Grafana starts with `admin/admin`.
- **Fix**: Make both mandatory:
  ```yaml
  GF_SECURITY_ADMIN_USER: ${GRAFANA_ADMIN_USER:?GRAFANA_ADMIN_USER is required}
  GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD:?GRAFANA_ADMIN_PASSWORD is required}
  ```
  Or generate a random password at first startup and store it in a shared secrets volume.

### 5. Redis in production compose allows empty password
- **File**: `docker-compose.optimized.yml:99`
- **Problem**: `--requirepass ${REDIS_PASSWORD:-}` allows empty password if `REDIS_PASSWORD` env var is unset or empty.
- **Fix**: Make mandatory:
  ```yaml
  --requirepass ${REDIS_PASSWORD:?REDIS_PASSWORD is required}
  ```

### 6. No Redis password in dev compose (unauthenticated Redis)
- **File**: `docker-compose.yml:8-20`
- **Problem**: Dev Redis has no `--requirepass` at all. While acceptable for local dev, it's inconsistent with production config and could lead to developers accidentally running production-like setups without auth.
- **Fix**: Add a comment explicitly noting this is intentionally unauthenticated for dev convenience. Consider an env var toggle.

### 7. CORS origins not validated — `*` allowed through misconfiguration
- **File**: `docker-compose.optimized.yml:26`
- **Problem**: `CORS_ORIGINS: ${CORS_ORIGINS:-http://localhost:3000}` — if someone sets `CORS_ORIGINS=*`, the application will accept any origin.
- **Fix**: Add runtime validation in the FastAPI app that rejects `*` as a CORS origin in production mode.

### 8. SECURITY.md contact email is `security@example.com`
- **File**: `SECURITY.md:17`
- **Problem**: Placeholder email is not actionable.
- **Fix**: Replace with a real contact (e.g., a specific team alias or GitHub security tab link), or clearly document that users must substitute their own.

---

## HIGH – Docker & Containerization

### 9. `Dockerfile.optimized` has wrong `uvicorn` module path in CMD
- **File**: `Dockerfile.optimized:133`
- **Problem**: `CMD ["uvicorn", "fastapi_dashboard.main:app", ...]` references `fastapi_dashboard.main:app` but the correct path used throughout the project is `src.dashboard.fastapi.main:app` (confirmed in dev `Dockerfile:31`, dev `docker-compose.yml:31`, production `docker-compose.optimized.yml:135`).
- **Fix**: Change to `CMD ["uvicorn", "src.dashboard.fastapi.main:app", ...]`

### 10. `Dockerfile.optimized` does not build the frontend UI
- **File**: `Dockerfile.optimized`
- **Problem**: Unlike the dev `Dockerfile` (lines 1-19, 38) which has a `frontend-builder` stage, copies `frontend/package*.json`, runs `npm ci && npm run build`, and copies the `dist/` artifact, the optimized Dockerfile has no frontend build step. When deploying with `Dockerfile.optimized`, the dashboard will have no UI.
- **Fix**: Either:
  - Add a multi-stage frontend build to `Dockerfile.optimized`, or
  - Document that `docker-compose.optimized.yml` must use the dev `Dockerfile` for builds that include the UI, and `Dockerfile.optimized` is backend-only.

### 11. `ci.yml` has typo in `docker-compose.optimized.yml` filename
- **File**: `.github/workflows/ci.yml:179`
- **Problem**: `file: docker-compose.optimimized.yml` (double `m` in optimized). The actual file is `docker-compose.optimized.yml`.
- **Fix**: Change to `file: docker-compose.optimized.yml`

### 12. Dev Docker Compose healthcheck uses `curl` but image may not have it
- **File**: `docker-compose.yml:63`, `Dockerfile`
- **Problem**: Dashboard healthcheck uses `curl -f http://localhost:8000/health` but the dev `Dockerfile` does not install `curl`. Only `Dockerfile.optimized` (line 64) installs it.
- **Fix**: Install `curl` in the dev `Dockerfile`, or change the healthcheck to use Python: `CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')"`.

---

## MEDIUM – CI/CD & GitHub Actions

### 13. CI `test` job uses `--cov=.` instead of configured source paths
- **File**: `.github/workflows/ci.yml:75`
- **Problem**: `pytest --cov=. --cov-report=xml ...` collects coverage on the entire project including `tests/`, `benchmarks/`, and non-source files, defeating the detailed `pyproject.toml` `[tool.coverage.run]` configuration.
- **Fix**: Change to `pytest --cov-report=xml --cov-report=term-missing -v` and let `pyproject.toml` handle source configuration.

### 14. Release workflow only builds `Dockerfile`, not `Dockerfile.optimized`
- **File**: `.github/workflows/release.yml:93-139`
- **Problem**: The build matrix at line 97-101 only includes `dockerfile: Dockerfile` with no suffix. `Dockerfile.optimized` is never built or released.
- **Fix**: Add `Dockerfile.optimized` to the matrix:
  ```yaml
  - dockerfile: Dockerfile.optimized
    image-suffix: "-optimized"
  ```

### 15. No Playwright E2E test job in CI
- **File**: `.github/workflows/ci.yml`
- **Problem**: Frontend section (`frontend:` job, line 81) only runs `vitest run` and `npm run build`. No Playwright e2e, visual, or audit tests run in CI despite `playwright.config.ts` and test specs existing.
- **Fix**: Add a Playwright CI job:
  ```yaml
  e2e:
    runs-on: ubuntu-24.04
    defaults:
      run:
        working-directory: ./frontend
    steps:
      - uses: actions/checkout@v6
      - name: Setup Node.js
        uses: actions/setup-node@v6
        with:
          node-version: "24"
          cache: "npm"
          cache-dependency-path: frontend/package-lock.json
      - name: Install dependencies
        run: npm ci
      - name: Build
        run: npm run build
      - name: Run Playwright tests
        run: npx playwright test
  ```

### 16. `dast.yml` uses `sleep 30` instead of health-based waiting
- **File**: `.github/workflows/dast.yml:21`
- **Problem**: `sleep 30` is a race condition-prone arbitrary wait. Application may not be ready in 30s on slower runners.
- **Fix**: Use healthcheck-based waiting:
  ```yaml
  - name: Wait for application
    run: |
      for i in {1..30}; do
        docker compose -f docker-compose.yml exec -T dashboard curl -sf http://localhost:8000/health && break
        sleep 2
      done
  ```

### 17. `dast.yml` references non-existent `.zap/rules.tsv`
- **File**: `.github/workflows/dast.yml:26`
- **Problem**: `rules_file_name: ".zap/rules.tsv"` — this file was not found in the repository.
- **Fix**: Verify the file exists at `.zap/rules.tsv` or remove the `rules_file_name` parameter.

### 18. Dependabot references non-existent GitHub teams as reviewers
- **File**: `.github/dependabot.yml:8,20,31,42`
- **Problem**: References `security-team`, `frontend-team`, `devops-team` which may not exist as GitHub teams in the organization.
- **Fix**: Either create the teams or remove the `reviewers:` field (Dependabot will then notify the repo maintainers by default).

---

## MEDIUM – Code Quality & Project Structure

### 19. Leftover one-off scripts in project root
- **Files**: `script.py`, `fix_file.py`, `fix_test.py`, `run_scan_squareup.py`, `_audit_runner.py`
- **Problem**: These are utility/patch scripts in the project root. `script.py` is a regex patcher that rewrites `src/execution/validators/runtime.py`. They are not part of the project deliverable.
- **Fix**: Move to `scripts/` directory or delete if no longer needed. Add `scripts/` to `.gitignore` if it becomes a garbage bin.

### 20. `pipeline.py` referenced in Dockerfile but does not exist
- **File**: `Dockerfile:32`
- **Problem**: `COPY pipeline.py ./` — this file does not exist in the project root.
- **Fix**: Remove the line if `pipeline.py` is not needed, or create it if it is a required entry point.

### 21. `resume.cfg` with target-specific state committed
- **File**: `resume.cfg`
- **Problem**: Contains `resume_from=www-vpn.www1-2.pad.squareup.com` — scan-specific state that should not be committed.
- **Fix**: Add `resume.cfg` to `.gitignore`. Delete from repo.

### 22. `src/output/` directory committed to repo
- **Files**: `src/output/` directory
- **Problem**: Output directories should be runtime artifacts, not committed. `.gitignore` only covers `output/` at root, not `src/output/`.
- **Fix**: Add `src/output/` to `.gitignore`. Remove from repo.

### 23. `nul` file in root
- **File**: `nul`
- **Problem**: Windows `nul` device artifact. Already in `.gitignore` (line 35) but may still be tracked.
- **Fix**: `git rm --cached nul` if tracked.

### 24. `pyrightconfig.json` uses Python module paths instead of filesystem paths
- **File**: `pyrightconfig.json:2-17`
- **Problem**: `include` entries like `"src.analysis"`, `"src.core"` use dot-notation (Python module names). Pyright expects filesystem paths like `"src/analysis"`, `"src/core"`.
- **Fix**: Change all dot-notation to slash-notation paths.

### 25. `alembic/env.py` has `target_metadata = None` — autogenerate disabled
- **File**: `alembic/env.py:26`
- **Problem**: `target_metadata = None` with comment "Until then, migrations must be written manually." SQLAlchemy autogenerate won't work.
- **Fix**: Import the project's SQLAlchemy `Base` and set `target_metadata = Base.metadata`. If no models exist yet, this is a known debt item to address when models are created.

### 26. `alembic.ini` hardcodes SQLite fallback URL
- **File**: `alembic.ini:60`
- **Problem**: `sqlalchemy.url = sqlite:///./pipeline.db` is a hardcoded fallback that will silently be used if no env var is set, masking misconfiguration.
- **Fix**: Remove the fallback from `alembic.ini` and ensure `alembic/env.py:get_url()` fails explicitly if `DATABASE_URL` is not set.

### 27. `mutmut_config.ini` uses `--timeout=60` but `pytest-timeout` not in deps
- **File**: `mutmut_config.ini:4`
- **Problem**: Runner uses `pytest -x --timeout=60` but `pytest-timeout` is not listed in `pyproject.toml` dev dependencies.
- **Fix**: Add `pytest-timeout` to dev dependencies, or remove `--timeout=60` from mutmut runner config.

### 28. Makefile has duplicate target definitions and unreachable rules
- **File**: `Makefile`
- **Problem**: Two `.PHONY` declarations (lines 4 and 26), duplicate `install`, `test`, `lint`, `format` targets. The first set (lines 4, 6-25) defines `venv` + activation-based rules that are unreachable because lines 28+ redefine `install` without venv. This is confusing and the `venv` rule is dead code.
- **Fix**: Consolidate into a single clean Makefile with all targets defined once. Remove duplicate `.PHONY` declarations.

### 29. Makefile uses Unix-specific `find` command
- **File**: `Makefile:52-56`
- **Problem**: `find . -type d -name __pycache__` etc. doesn't work on Windows without WSL.
- **Fix**: Provide Windows-compatible commands in README or add a `.PHONY` `clean` target using Python for cross-platform compatibility.

### 30. `.editorconfig` says Makefile uses tabs but Makefile uses spaces
- **Files**: `.editorconfig:24`, `Makefile`
- **Problem**: `.editorconfig` specifies `indent_style = tab` for Makefile, but actual Makefile uses space indentation.
- **Fix**: Either convert Makefile to tabs (standard for Makefiles) or remove the `[Makefile]` section from `.editorconfig`.

---

## LOW – Documentation & UX

### 31. `README.md:16` has malformed Markdown header
- **File**: `README.md:16`
- **Problem**: `-### Prerequisites` has an extra dash prefix. Should be `### Prerequisites`.
- **Fix**: Remove the leading dash.

### 32. Multiple overlapping documentation files create confusion
- **Files**: `README.md`, `GEMINI.md`, `PLANS.md`, `frontend.md`, `docs/*.md`
- **Problem**: Overlapping docs: `README.md` (user-facing), `GEMINI.md` (AI agent instructions), `PLANS.md` (autonomous execution roadmap), `frontend.md` (frontend reference), `docs/` (detailed guides). Users and contributors don't know which to read.
- **Fix**: Clearly distinguish by renaming: `README.md` → user guide, `AGENTS.md` → AI agent instructions, `ROADMAP.md` → project roadmap, `frontend.md` stays, `docs/` becomes a technical reference. Add a `CONTRIBUTING.md`.

### 33. `frontend.md` mentions undeletable `cyberpunk/` folder
- **File**: `frontend.md:480-482`
- **Problem**: References `frontend/src/styles/cyberpunk/*` folder that cannot be deleted due to OS `EPERM` on Windows.
- **Fix**: Investigate and remove with elevated permissions, or document as known Windows-specific debt.

### 34. No `CONTRIBUTING.md`
- **Problem**: No contribution guidelines for open-source contributors.
- **Fix**: Add `CONTRIBUTING.md` with: local dev setup, testing requirements, PR template reference, pre-commit setup instructions.

### 35. `docs/` lacks a README/index
- **Problem**: `docs/` has 15 files with no entry point or table of contents.
- **Fix**: Add `docs/README.md` with a linked table of contents to all documentation files.

---

## LOW – Build & Configuration

### 36. Root-level `package-lock.json` should not exist
- **File**: `package-lock.json` (root)
- **Problem**: This is a Python project. The `package-lock.json` belongs only in `frontend/` where `package.json` lives.
- **Fix**: Remove root `package-lock.json`. Verify `frontend/package-lock.json` is the only one.

### 37. `playwright.config.ts` webServer command references undefined script
- **File**: `playwright.config.ts:31`
- **Problem**: `command: 'cyber-dashboard-fastapi'` — this script is not defined in `pyproject.toml` `[project.scripts]`. Only `cyber-dashboard` and `cyber-pipeline` exist.
- **Fix**: Change to `command: 'cyber-dashboard --port 8000'` or `npx uvicorn src.dashboard.fastapi.main:app --port 8000`.

### 38. `.dockerignore` excludes `plans/` which doesn't exist as a directory
- **File**: `.dockerignore:17`
- **Problem**: `plans/` exclusion references a directory that doesn't exist (only `PLANS.md` file exists at root).
- **Fix**: Remove `plans/` from `.dockerignore`.

### 39. Python 3.14 requirement is very aggressive
- **File**: `pyproject.toml:5`
- **Problem**: `requires-python = ">=3.14"` — Python 3.14 is extremely new. Most CI environments and dev machines won't have it. This limits adoption.
- **Fix**: Consider supporting Python 3.12+ (many features used are available in 3.12). If 3.14 is truly required (e.g., for specific features), document why prominently.

### 40. Dependabot has no group configuration
- **File**: `.github/dependabot.yml`
- **Problem**: All updates create separate PRs. Minor/patch updates of related packages (e.g., all `opentelemetry-*` packages) can't be batched.
- **Fix**: Add grouping:
  ```yaml
  groups:
    python-observability:
      patterns: ["opentelemetry-*"]
    python-http:
      patterns: ["httpx", "aiohttp", "requests"]
  ```

---

## LOW – Testing Improvements

### 41. Coverage thresholds too uniform — critical modules need higher coverage
- **File**: `pyproject.toml:122-144`
- **Problem**: Every module has an identical `80%` threshold. Security-critical modules (`src.execution`, `src.exploitation`, `src.fuzzing`, `src.infrastructure.security`) should have 90-95% coverage, not 80%.
- **Fix**: Increase thresholds for security-critical modules to 90-95%.

### 42. No explicit unit vs integration test split in CI
- **File**: `.github/workflows/ci.yml:52-75`
- **Problem**: `pytest` runs all tests without distinguishing unit from integration. Integration tests typically need services (Redis, etc.) and should run separately.
- **Fix**: Use `pytest tests/unit` for the CI job, and add a separate integration job that uses `docker compose` to start required services.

### 43. Mutation testing has no failure threshold
- **File**: `.github/workflows/mutation.yml:22-25`
- **Problem**: `mutmut run` runs but there's no threshold that fails the build if mutation score drops below an acceptable level.
- **Fix**: Use `mutmut results --minimum-surviving=0.7` or similar threshold to fail CI when mutation coverage is too low.

### 44. No pre-commit validation in CI
- **File**: `.github/workflows/ci.yml`
- **Problem**: `.pre-commit-config.yaml` exists but no CI job runs `pre-commit run --all-files`.
- **Fix**: Add a job:
  ```yaml
  pre-commit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with: { python-version: "3.14" }
      - run: pip install pre-commit
      - run: pre-commit run --all-files
  ```

---

## Priority Summary

| Priority | Count | Items |
|----------|-------|-------|
| Critical | 8 | #1-8 (secrets, auth, CORS) |
| High | 4 | #9-12 (Docker fixes) |
| Medium | 13 | #13-25 (CI, root cleanup, config) |
| Low | 17 | #26-43 (docs, testing, config refinements) |

## Recommended Execution Order

**Week 1 — Security (Critical)**
- #2, #3 (APP_SECRET_KEY mandatory in compose files)
- #4 (Grafana credentials mandatory)
- #5, #6 (Redis auth consistency)
- #7 (CORS validation at runtime)
- #1 (audit .env tracking)

**Week 2 — Docker & Build (High)**
- #9 (fix CMD import path in Dockerfile.optimized)
- #10 (add frontend build to Dockerfile.optimized or document limitation)
- #11 (fix CI typo)
- #12 (dev Dockerfile curl installation or healthcheck fix)

**Week 3 — CI/CD (Medium)**
- #13 (fix coverage command in CI)
- #14 (build both Dockerfiles in release)
- #15 (add Playwright E2E to CI)
- #16, #17, #18 (fix DAST workflow, Dependabot teams)
- #19-23 (clean up root artifacts)
- #24 (fix pyrightconfig.json)
- #25 (fix alembic model metadata)

**Week 4+ — Documentation & Polish (Low)**
- #26-30 (alembic, mutmut, Makefile, .editorconfig)
- #31-35 (documentation improvements)
- #36-40 (build/config refinements)
- #41-44 (testing improvements)