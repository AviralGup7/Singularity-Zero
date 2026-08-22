# Cyber Security Test Pipeline

An enterprise-grade, distributed API and web application security testing pipeline featuring asynchronous DAG orchestration, an active-learning ML severity engine, resilient circuit-breaking, and a real-time React 19 operator cockpit. Built for authorized offensive security assessments, automated bug bounty reconnaissance, and continuous DevSecOps pipeline verification.

---

## 🌟 Key Architecture Highlights

- **Asynchronous DAG Orchestration**: Non-blocking stage lifecycle (`Recon` → `Probing` → `Exploitation` → `Learning` → `Reporting`) with speculative dispatch, wall-clock deadline budgeting, and dynamic checkpoint recovery (`src/pipeline/`).
- **Resilient Circuit Breaking & Rate Limiting**: Built-in 3-state Circuit Breaker (`Closed`, `Open`, `Half-Open`) with Redis/SQLite persistence and automated HTTP 429 `Retry-After` header extraction (`src/resilience/`).
- **Frontier CRDT State Engine**: Causally consistent LWW-Set CRDTs indexed by Hybrid Logical Clocks (HLCs), delivering $O(1)$ space per node and append-only state journal audits (`src/frontier/`).
- **Closed-Loop Active Learning**: Continuous feedback loop utilizing XGBoost and Scikit-Learn (with pure NumPy fallback) to calibrate severity scores and suppress duplicate false positives based on operator triage (`src/learning/`).
- **Hardware-Isolated Exploit Sandbox**: Validation PoCs run safely inside a `wasmtime` WebAssembly sandbox or AST-validated process isolation, preventing host machine contamination (`src/sandbox/`).
- **Real-Time 3D Attack Cockpit**: React 19 + Three.js instanced rendering of attack graphs at 60 FPS, with interactive request/response replay, virtualized finding tables, and live WebSocket telemetry (`frontend/src/`).

---

## ⚡ Quick Start

### 1. Set Up Environment (Python 3.13+ Required)
```bash
# Clone the repository
git clone https://github.com/AviralGup7/Singularity-Zero.git cyber-pipeline
cd cyber-pipeline

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\Activate.ps1

# Install package and development tools
pip install -e ".[dev]"
```

### 2. Build the React Dashboard
```bash
cd frontend && npm install && npm run build && cd ..
```

### 3. Initialize Configuration & Scope
```bash
cp configs/config.example.json configs/config.json
cp configs/api_keys.example.json configs/api_keys.json
cp .env.example .env
echo "example.com" > configs/scope.txt
```

### 4. Launch the Unified Operator Console
```bash
# Starts both the FastAPI backend and background worker on port 8000
cstp launch --host 127.0.0.1 --port 8000 --concurrency 2
```

Navigate to **http://localhost:8000/** to access the operator command center.

---

## 💻 CLI Usage

Execute automated scans directly from your terminal:

```bash
# Validation dry-run (No outbound packets sent)
cstp scan run --config configs/config.json --scope configs/scope.txt --dry-run

# Execute full security scan
cstp scan run --config configs/config.json --scope configs/scope.txt

# Run system doctor to verify environment & external tool dependencies
cstp system doctor

# Auto-download pre-compiled binaries (nuclei, httpx, subfinder, katana, gau)
cstp system setup
```

---

## 📚 Documentation Index

- [Documentation Index](docs/index.md) — Master portal to all technical and architectural guides.
- [Getting Started](docs/getting-started.md) — Step-by-step local setup, scoping, and scan execution.
- [Codebase Map](docs/codebase.md) — Comprehensive guide to all 35 packages in `src/`, `frontend/`, `tests/`, and `configs/`.
- [Architecture Overview](docs/architecture-overview.md) — Subsystem map and engineering design patterns.
- [Architecture Deep Dive](docs/architecture.md) — Distributed DAG engine, actor mesh, and CRDT state engine.
- [Commands Reference](docs/commands.md) — CLI flags, subcommands, and runtime arguments.
- [Environment Variables](docs/environment-variables.md) — Catalog of configuration parameters.
- [Testing & CI Guide](docs/testing.md) — Unit, integration, and architecture test suites.
- [Frontend Handbook](docs/frontend.md) — React 19, Zustand stores, Tailwind 4, and 3D Cockpit.
- [Observability Catalog](docs/OBSERVABILITY_CATALOG.md) — Prometheus metrics, tracing spans, and Grafana dashboards.
- [Failure Modes & Diagnostics](docs/FAILURE_MODES.md) — Stage failure taxonomy and zero-finding troubleshooting.
- [CI/CD Integration](docs/ci-cd-integration.md) — SARIF reports, GitHub Actions, and policy gates.

---

## 🛡️ Responsible Use & License

This tool is designed exclusively for authorized security audits, penetration testing, and vulnerability research on systems where explicit permission has been granted.

MIT License. See [LICENSE](LICENSE) for details.