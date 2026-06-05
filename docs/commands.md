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
cyber start dashboard --host 127.0.0.1 --port 8000 --workers 4 --reload --log-level INFO
```

### 4. Distributed Workers
Start a background distributed queue worker separately:
- **Start Worker**:
  ```bash
  cyber start worker --queue security-pipeline --concurrency 2
  ```
- **Worker with Checkpoint Replication**:
  ```bash
  cyber start worker --queue security-pipeline --concurrency 2 --replication
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
