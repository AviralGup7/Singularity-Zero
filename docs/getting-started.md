# Getting Started

Python 3.13+ is required (`requires-python = ">=3.13"`). This page is the local bootstrap. CLI flags live in [commands.md](commands.md). Environment variables live in [environment-variables.md](environment-variables.md).

## 1. Install

```bash
git clone https://github.com/AviralGup7/Singularity-Zero.git
cd Singularity-Zero
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## 2. Dashboard (optional)

```bash
cd frontend && npm install && npm run build && cd ..
```

Local `create_app` (non-production) setdefaults `DASHBOARD_GUEST_ACCESS_ENABLED=true` and `DASHBOARD_AUTH_DISABLED=true` when unset, and generates `APP_SECRET_KEY` if missing. Production must set real secrets.

## 3. Config and scope

```bash
cp configs/config.example.json configs/config.json
cp configs/api_keys.example.json configs/api_keys.json
cp .env.example .env            # if present
echo "example.com" > configs/scope.txt
```

Keep the three config trees separate. Do not invent a kernel / God-container:

| Tree | Prefix / source | Owner |
|---|---|---|
| Scan | JSON `ValidatedPipelineConfig` | `cstp scan` / `src.pipeline.runtime` |
| Dashboard | `DASHBOARD_*` | FastAPI |
| Queue | `QUEUE_*` | workers |

`AppSettings` (`CYBER_*`) is tests-only.

## 4. Run

```bash
# Operator console + worker (local)
cstp launch --host 127.0.0.1 --port 8000 --concurrency 2

# Headless scan
cstp scan run --config configs/config.json --scope configs/scope.txt --dry-run
cstp scan run --config configs/config.json --scope configs/scope.txt

# Environment check
cstp system doctor
cstp system setup
```

Open http://127.0.0.1:8000/. Live CLI is single-node quorum-1. `NetworkRaftTransport` is library code, not a running mesh.

## 5. Exit codes (operator lattice)

`derive_job_and_exit` (`src/jobs/run_outcome.py`) is the named mapping. Dashboard reap uses it when a stage map is supplied.

| Code | JobStatus | Meaning |
|---|---|---|
| 0 | COMPLETED | Clean / under policy |
| 2 | COMPLETED | Findings exceeded policy |
| 4 | COMPLETED + `degraded=True` | DEGRADED / SKIPPED_FAILED |
| 3 | FAILED | Infra / fatal stage / attach failure |
| 1 | FAILED | Unclassified error / lock collision |
| 7 / 130 | STOPPED | Suspend / interrupt |

Attach failure (`attach_pipeline_authority`) is fail-closed **exit 3**. Scheduler OOM (1), suspend (7), and SIGINT (130) still bypass the lattice.

Dashboard jobs append `--force-fresh-run` unless `force_fresh=False`. The UI default never resumes.

## 6. Next

- [commands.md](commands.md) — CLI reference
- [architecture.md](architecture.md) — I1–I37 contract
- [flowchart.md](flowchart.md) — F-004 live scan path
- [FAILURE_MODES.md](FAILURE_MODES.md) — triage
- [testing.md](testing.md) — local tests (smallest slice; full suite is CI)
