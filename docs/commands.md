# Commands Reference

This guide provides a reference for all CLI operations using the unified `cyber` command engine.

---

## 🚀 Unified Runtime Commands (`cyber`)

The system uses a centralized command engine `cyber` (installed via `pip install -e .`). You can also execute it directly via `python src/cli.py` or `python -m src.cli`.

### 1. Unified Local Launcher (Cockpit + Worker)
Start the dashboard server and a background queue worker in a single process. This is the recommended command for local development:
```bash
cyber launch --host 127.0.0.1 --port 8000 --concurrency 2 --queue security-pipeline
```

### 2. Pipeline Scans
Trigger a security scan workflow directly from the command line:
- **Full Scan**:
  ```bash
  cyber scan run --config configs/config.json --scope scope.txt
  ```
- **Dry-run (Validate only - no outbound traffic)**:
  ```bash
  cyber scan run --config configs/config.json --scope scope.txt --dry-run
  ```
- **Force Fresh Run (Ignore checkpoints)**:
  ```bash
  cyber scan run --config configs/config.json --scope scope.txt --fresh
  ```

### 3. Dashboard Operations
Start the FastAPI security orchestration dashboard separately:
```bash
cyber start dashboard --host 127.0.0.1 --port 8000 --workers 4 --log-level INFO
```
For development with auto-reload (single worker):
```bash
cyber start dashboard --host 127.0.0.1 --port 8000 --reload --log-level INFO
```

### 4. Distributed Workers
Start a background distributed queue worker separately:
- **Start Worker**:
  ```bash
  cyber start worker --queue security-pipeline --concurrency 2
  ```
- **Custom Worker ID**:
  ```bash
  cyber start worker --worker-id node-alpha-01
  ```

### 5. System Maintenance & Health
- **Check Infrastructure Status** (Redis, Workspace, DB, Python Engine):
  ```bash
  cyber system status
  ```
- **Environment & Config Doctor** (Verify dependencies, env vars, config integrity):
  ```bash
  cyber system doctor
  ```
  Exit codes: `0` = all checks passed, `2` = missing system binaries, `3` = `.env` file issues, `5` = config integrity failure.
- **Automated Tool Setup** (Auto-detect platform and download Go binaries like `nuclei`, `httpx`, `subfinder` locally):
  ```bash
  cyber system setup
  ```
  Or specify a target folder:
  ```bash
  cyber system setup --dir /path/to/custom/bin
  ```
- **Clean Up Checkpoints & Artifacts**:
  ```bash
  cyber system cleanup --days 7
  ```

### 6. Custom Plugin Scaffolding
Scaffold a new custom scanning plugin with clean absolute imports and automatic registration:
- **Interactive Prompts Scaffolding**:
  ```bash
  cyber plugin new
  ```
- **Parameter Scaffolding**:
  ```bash
  cyber plugin new --name custom_scanner --category recon
  ```
  Options:
  - `--name`: Name of the new plugin (alphanumeric/underscore).
  - `--category`: Scaffolding category type (`recon`, `exploit`, `reporting`).

### 7. CI/CD Integration Flags
All flags are accepted by `cyber scan run`, the `cyber-pipeline` legacy wrapper, and the
`run_orchestrator` programmatic entry point. See [CI/CD Integration Guide](ci-cd-integration.md)
for the full schema, exit-code table, and CI examples.
- **Apply a declarative policy file**:
  ```bash
  cyber scan run --config configs/config.json --scope scope.txt --policy policy.toml
  ```
- **Incremental scan (re-crawl only URLs mapped to files changed since `--base-ref`)**:
  ```bash
  cyber scan run --config configs/config.json --scope scope.txt --incremental --base-ref origin/main
  ```
- **Override the detected branch** (used by `[on_findings] branch_glob`):
  ```bash
  cyber scan run --config configs/config.json --scope scope.txt --branch feature/login
  ```
- **Restore legacy single-exit-code behaviour** (collapses exit codes 2/3/4 → 1):
  ```bash
  cyber-pipeline --config configs/config.json --scope scope.txt --legacy-exit-codes
  ```

| Flag | Effect |
|------|--------|
| `--policy PATH`        | Load a `policy.toml` file; defaults are conservative (≤5 high, ≤50 medium per run). |
| `--incremental`        | Restrict the URL set to URLs mapped to files changed since `--base-ref`. |
| `--base-ref REF`       | Git ref (branch/tag/commit) for the incremental diff baseline. |
| `--branch NAME`        | Override the detected branch (auto-detected from `GITHUB_REF_NAME` / `CI_COMMIT_REF_NAME` / `BRANCH_NAME` / `CYBER_BRANCH`). |
| `--legacy-exit-codes`  | Collapse 2/3/4 → 1 for backward compatibility with existing CI scripts. |

Every run produces `<run_dir>/report.sarif` (SARIF 2.1.0) for native ingestion by GitHub
Code Scanning, GitLab `artifacts.reports.sast`, and Azure DevOps SARIF tabs. Policy
verdicts are emitted on the event bus as `INGRESS_POLICY_RESULT` events and persisted
to `<run_dir>/policy_evaluation.json` for audit.

---

## 🛠️ Development & Debug

### Testing
- **Run All Tests**: `pytest`
- **Unit Tests**: `pytest tests/unit/`
- **Integration Tests**: `pytest tests/integration/`
- **Architecture Rules**: `pytest tests/architecture/`

### Linting & Formatting
- **Lint & Fix**: `ruff check . --fix`
- **Format**: `ruff format .`
- **Type Check**: `mypy .`

### Database (Alembic)
- **Upgrade to Latest**: `alembic upgrade head`
- **Downgrade to Base**: `alembic downgrade base`
- **Generate Auto-Migration**: `alembic revision --autogenerate -m "description"`

---

## 🐳 Docker

- **Dev Environment**: `docker compose up --build`
- **Optimized (Prod)**: `docker compose -f docker-compose.optimized.yml up --build`

---

## 🔄 Legacy Entrypoint Wrappers

For backward compatibility, individual legacy script wrappers remain available (defined in `pyproject.toml`):
- **Pipeline Runner**: `cyber-pipeline` (aliases `cyber scan run`)
- **Dashboard Server**: cyber-dashboard was removed; use `cyber start dashboard` directly
- **Queue Worker**: `cyber-worker` (aliases `cyber start worker`)
