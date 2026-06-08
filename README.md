# Cyber Security Test Pipeline

An automated API and web-application security testing pipeline with
distributed orchestration, an active-learning severity model, and a
real-time React dashboard.  Designed for authorized security testing.

---

## Highlights

- **Distributed pipeline orchestrator** that runs reconnaissance, active
  probing, exploitation, enrichment, and reporting as a DAG of stages
  with retry, circuit-breaker, and resume support.
- **Actor mesh** for elastic scan orchestration: tasks are encapsulated
  in stateful actors (built on pykka) that can be checkpointed to a
  Redis-backed write-ahead log and rehydrated on another node.
- **Causal state engine**: cluster-wide state is stored in Hybrid
  Logical Clock (HLC) LWW-Set CRDTs that give causal ordering in
  **O(1) space per node**, with Redis pub/sub Bloom snapshots for
  cross-node membership reconciliation.
- **Closed-loop learning**: an XGBoost + scikit-learn classifier with a
  pure-NumPy fallback is retrained on analyst triage signals, with
  calibrated severity scores and false-positive suppression.
- **In-process evasion controls** (HMM-driven header/JA3 mutation and
  timing jitter) used in authorized red-team engagements.
- **3D attack-chain cockpit**: React Three Fiber + Three.js instanced
  rendering of the Kuzu attack-graph at 60 FPS, with a control deck
  for target scoping, module toggles, and live stage polling.
- **Sandboxed exploit validation**: PoCs run in a wasmtime WebAssembly
  sandbox; dynamically loaded Python plugins are AST-validated and
  executed in a separate process.

For a non-marketing map of these subsystems to the modules that
implement them, see docs/architecture-overview.md.

---

## Quick Start

`ash
# 1. Setup environment (Python 3.12 or newer required)
python3.12 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# 2. Build the React frontend (React 19 + R3F + Tailwind 4)
cd frontend && npm install && npm run build && cd ..

# 3. Start the dashboard (Redis recommended; falls back to in-memory)
python -m src.dashboard.fastapi.app --host 0.0.0.0 --port 8000
`

Then open http://localhost:8000/ for the operator console.

## Documentation

* docs/getting-started.md — walkthrough and first scan
* docs/architecture-overview.md — non-marketing module map
* docs/architecture.md — branded, capability-focused walkthrough
* docs/FAILURE_MODES.md — interpreting "zero findings" reports
* docs/environment-variables.md — every env var the system reads
* docs/api-reference.md — full reference
* CONTRIBUTING.md — development workflow and code style

## System control

- **Ops Command Center** — React 19 dashboard at http://localhost:8000/.
- **Security Cockpit** — 3D instanced-rendered threat graphs.
- **Mesh Health** — Bloom reconciliation and HLC state.

## License

Authorized security testing only.  See LICENSE.