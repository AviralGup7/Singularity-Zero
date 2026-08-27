# Commands Reference

This document provides a complete reference for all CLI operations, service management commands, and development utilities using the unified `cstp` command engine.

---

## 🚀 Unified CLI Engine (`cstp`)

The command engine is installed via `pip install -e .` and provides the `cstp` CLI. You can also invoke it directly with `python -m src.cli`.

### 1. Unified Launcher (Dashboard + Worker)
Spins up both the FastAPI operator cockpit and a background queue worker in a single process. Recommended for local operation:
```bash
cstp launch --host 127.0.0.1 --port 8000 --concurrency 2 --queue security-pipeline
```

### 2. Pipeline Scans (`cstp scan`)
Execute automated vulnerability scans against configured target scopes:
```bash
# Standard scan
cstp scan run --config configs/config.json --scope configs/scope.txt

# Validation dry-run (No outbound network traffic generated)
cstp scan run --config configs/config.json --scope configs/scope.txt --dry-run

# Force fresh run (Ignore prior checkpoints)
cstp scan run --config configs/config.json --scope configs/scope.txt --fresh
```

### 3. Service Lifecycle (`cstp start`)
Manage individual distributed subsystem processes:

- **Start Dashboard API**:
  ```bash
  # Production multi-worker mode
  cstp start dashboard --host 0.0.0.0 --port 8000 --workers 4 --log-level INFO

  # Local development with hot-reload
  cstp start dashboard --host 127.0.0.1 --port 8000 --reload --log-level DEBUG
  ```

- **Start Distributed Queue Worker**:
  ```bash
  cstp start worker --queue security-pipeline --concurrency 4 --worker-id worker-node-01
  ```

### 4. System Maintenance & Health (`cstp system`)
- **System Doctor** (Verifies Python environment, binary dependencies, and configuration integrity):
  ```bash
  cstp system doctor
  ```
  *Exit Codes: `0` = All checks passed, `2` = Missing system binaries, `3` = `.env` configuration error, `5` = Invalid configuration.*

- **Infrastructure Health Probes** (Inspects Redis backplane, workspace root, output store directory, and Python runtime):
  ```bash
  cstp system status
  ```

- **Automated External Tool Setup** (Downloads and installs required Go binaries: `subfinder`, `httpx`, `nuclei`):
  ```bash
  cstp system setup --dir .tools/bin
  ```

- **Prune Old Artifacts & Checkpoints** (Retains specified number of latest runs):
  ```bash
  cstp system cleanup --output-root output --keep-target-runs 2 --keep-launcher-runs 5
  ```

### 5. Plugin Scaffolding (`cstp plugin`)
Scaffold new dynamic security analyzer plugins with pre-configured schemas and contracts:
```bash
cstp plugin new --name custom_header_audit --category recon
```

---

## ⚙️ Advanced Pipeline Runtime Options (`python -m src.pipeline.runtime`)

For CI/CD pipelines, headless runners, and automated orchestration:

```bash
python -m src.pipeline.runtime \
  --config configs/config.json \
  --scope configs/scope.txt \
  --policy policy.toml \
  --incremental \
  --base-ref origin/main \
  --resume-from <checkpoint_run_id> \
  --wal-replay replay \
  --max-duration 3600
```

| Flag | Purpose | Default |
|---|---|---|
| `--config PATH` | Path to JSON pipeline configuration | Required |
| `--scope PATH` | Path to target scope text file | Required |
| `--policy PATH` | Path to `policy.toml` compliance policy gate | `None` |
| `--incremental` | Re-scan only URLs and routes modified since `--base-ref` | `False` |
| `--base-ref REF` | Git branch/commit ref used for incremental diffing | `None` |
| `--branch NAME` | Branch name override for `[on_findings] branch_glob` | `None` |
| `--resume-from ID` | Resume execution from a previously persisted checkpoint ID | `None` |
| `--wal-replay MODE`| Journal recovery mode: `verify`, `replay`, `dry-run` | `replay` |
| `--max-duration SEC`| Wall-clock budget in seconds before graceful termination (exits 3) | `None` |
| `--dry-run` | Validate DAG and contracts without issuing external probes | `False` |
| `--legacy-exit-codes` | Normalize granular exit codes (2/3/4) to standard 1 | `False` |
| `--force-fresh-run` | Ignore prior checkpoints (CLI). Dashboard jobs pass this unless `force_fresh=False` | `False` |
| `--skip-crtsh` | Skip passive crt.sh certificate transparency log collection | `False` |
| `--refresh-cache` | Force-bypass cached subdomain and URL sets | `False` |
| `--replay ARCHIVE` | Path to a `.tar.gz` artifact pack to replay and verify parity | `None` |
| `--validate-config` | Validate configuration syntax and schema without executing | `False` |
| `--replay-stage STAGE` | Re-execute only a single stage from a captured run (requires `--run-id`) | `None` |
| `--run-id ID` | Target run ID to source stage trace from | `None` |
| `--replay-traces ID` | Load and replay all stages from a traced run ID | `None` |
| `--trace-dir DIR` | Directory containing stage trace JSONL files | `.ai/traces` |
| `--ci-fail-on-severity LVL` | Exit non-zero when findings at/above severity (`critical`..`info`) exist | `None` |
| `--continuous` | Enable continuous monitoring loop mode | `False` |
| `--monitor-interval SEC` | Cycle duration in seconds for continuous monitoring | `3600` |
| `--asset-diff-only` | Only scan new/changed assets since the last checkpoint | `False` |
| `--import-burp-issues PATH` | Ingest Burp Suite `issues.xml` export | `None` |
| `--import-burp-sitemap PATH` | Ingest Burp Suite SiteMap JSON export | `None` |
| `--burp-collaborator-url URL` | Burp Collaborator server URL for out-of-band AST polling | `None` |

### Exit codes

Named lattice: `src/jobs/run_outcome.py` `derive_job_and_exit`.

| Code | JobStatus | Meaning |
|---|---|---|
| 0 | COMPLETED | Clean / under policy |
| 2 | COMPLETED | Findings exceeded policy |
| 4 | COMPLETED + degraded | DEGRADED / SKIPPED_FAILED |
| 3 | FAILED | Infra, fatal recon, **attach fail-closed** |
| 1 | FAILED | Unclassified / lock collision (lattice bypass) |
| 7 / 130 | STOPPED | Suspend / interrupt (lattice bypass) |

Attach (`attach_pipeline_authority`) failure is fail-closed **exit 3**. After attach, `apply_authority_recovery` runs.

---

## 🧪 Development, Quality & Test Commands

- **Run Test Suite**:
  ```bash
  pytest tests/unit/
  pytest tests/integration/
  pytest tests/architecture/
  ```

- **Code Formatting & Linting**:
  ```bash
  ruff format .
  ruff check . --fix
  ```

- **Static Type Checking**:
  ```bash
  mypy src/
  ```

- **Database Migrations (Alembic)**:
  ```bash
  alembic upgrade head
  alembic revision --autogenerate -m "add_table"
  ```

---

## 🐳 Docker Deployment Commands

```bash
# Standard Full-Stack Development Compose
docker compose up --build

# Production Optimized Composition
docker compose -f docker-compose.optimized.yml up --build -d
```
