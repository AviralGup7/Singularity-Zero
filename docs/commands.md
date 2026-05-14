# Commands Reference

This guide provides a reference for common CLI operations.

## 🚀 Runtime Commands

### Pipeline Operations
- **Full Scan**:
  ```bash
  cyber-pipeline --config configs/config.json --scope scope.txt
  ```
- **Dry-run (Validate only)**:
  ```bash
  cyber-pipeline --config configs/config.json --scope scope.txt --dry-run
  ```
- **Force Fresh Run** (Ignore checkpoints):
  ```bash
  cyber-pipeline --config configs/config.json --scope scope.txt --force-fresh-run
  ```
- **Replay Archive**:
  ```bash
  cyber-pipeline --replay path/to/artifacts.tar.gz
  ```

### Local-Mesh Workers
- **Start Worker**:
  ```bash
  cyber-worker --enable-discovery --capabilities browser heavy_compute
  ```
- **Worker with Checkpoint Replication**:
  ```bash
  cyber-worker --enable-discovery --enable-checkpoint-replication
  ```

### Dashboard
- **Start Dashboard**:
  ```bash
  cyber-dashboard --port 8000
  ```

---

## 🛠️ Development & Debug

### Testing
- **Run All Tests**: `pytest -q`
- **Unit Tests**: `pytest tests/unit -q`
- **Integration Tests**: `pytest tests/integration -q`
- **Architecture Rules**: `pytest tests/architecture -q`

### Linting & Formatting
- **Lint & Fix**: `ruff check . --fix`
- **Format**: `ruff format .`
- **Type Check**: `mypy .`

### Database (Alembic)
- **Upgrade to Latest**: `alembic upgrade head`
- **Downgrade to Base**: `alembic downgrade base`

---

## 🐳 Docker

- **Dev Environment**: `docker compose up --build`
- **Optimized (Prod)**: `docker compose -f docker-compose.optimized.yml up --build`

---

## 🔍 Troubleshooting

### Environment
- **Log Level**: `LOG_LEVEL=DEBUG cyber-pipeline ...`
- **Config Validation**: `cyber-pipeline --config config.json --scope scope.txt --validate-config`

### Artifacts
- **Clear Cache**: `cyber-pipeline --refresh-cache ...`
- **Manual Cleanup**: `rm -rf output/<target>/.cache`
