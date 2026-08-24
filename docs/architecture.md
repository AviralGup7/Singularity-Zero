# Project Architecture: Cyber Security Test Pipeline

## Implementation Status & Engineering Ground Truth

This document outlines the architecture, distributed execution model, resilience mechanisms, and cognitive analysis components of the Cyber Security Test Pipeline. The table below delineates production-shipped components from research and prototype systems:

| Subsystem / Capability | Current Status | Code Location |
|---|---|---|
| **DAG Pipeline Orchestrator** | **Production** — Async DAG builder, actor scheduler, stage lifecycle, speculative dispatch | `src/pipeline/services/pipeline_orchestrator/`, `src/pipeline/engine.py` |
| **Resilience & Circuit Breaking** | **Production** — tool breaker is `src/pipeline/services/circuit_breaker.py`; Retry-After parser is `src/resilience/retry_after.py`. There is no live `src/resilience/circuit_breaker.py`. | `src/pipeline/services/circuit_breaker.py`, `src/resilience/retry_after.py` |
| **Unified Hierarchical Cache** | **Production** — In-memory LRU + SQLite/Redis tiered cache with single-flight request coalescing | `src/pipeline/unified_cache/`, `src/cache/` |
| **Frontier State & CRDT Engine** | **Production** — LWW-Set CRDTs keyed by Hybrid Logical Clocks (HLC), journaled state deltas | `src/frontier/`, `src/core/frontier/` |
| **Tamper-Evident Audit Ledger** | **Production** — Cryptographic HMAC-SHA256 chained audit trail for administrative and scan events | `src/auth/audit.py`, `src/console/audit.py` |
| **Active & Passive Analyzers** | **Production** — Multi-stage detectors for SQLi, XSS, SSRF, JWT, CSP, HTTP/2 smuggling | `src/analysis/active/`, `src/analysis/passive/` |
| **ML Severity & Active Learning** | **Production** — in-process calibrated logreg priors (`src/intelligence/severity_model.py`), not XGBoost. `src/intel/` is an offline console vote store, not this model. | `src/intelligence/severity_model.py`, `src/learning/` |
| **Adaptive Nuclei Tag Optimizer** | **Production** — Per-tag precision/recall/F1 telemetry tracking with dynamic config overrides | `src/learning/nuclei_tag_optimizer.py` |
| **WASM / Process Sandbox** | **Optional / incomplete** — wasmtime is an extra; default `.wasm` verifiers are stubs. `src/sandbox/` is only a feature-flag facade. Live plugin isolation is `src/core/plugins/sandbox.py`. | `src/execution/frontier/wasm.py`, `src/core/plugins/sandbox.py` |
| **3D Cockpit & Real-time Console** | **Production** — React 19 + Three.js instanced attack graph rendering, Zustand stores, WebSockets | `frontend/src/`, `src/websocket_server/` |
| **Distributed Actor Mesh** | **Production (Single-node & P2P)** — Pykka/Asyncio workers with SWIM gossip discovery and shard balancing | `src/mesh/`, `src/infrastructure/mesh/` |
| **Attack Graph & Path Prediction** | **Heuristic** — in-process threat-graph dicts and campaign builder. Not a live Kuzu GCN. | `src/intelligence/graph/`, `src/intelligence/campaigns/` |
| **Formal ExecutionRequest & Contract of Intent** | **Production** — Immutable `ExecutionRequest` / `ExecutionResult` handoff, cryptographic `ScopeToken` authorization, and stateless worker execution | `src/decision/models.py`, `src/decision/authorization.py`, `src/execution/request_executor.py`, `src/core/contracts/execution_request.py` |

---

## 🏛️ Core Principles & Execution Planes

### 1. The Unified 7-Layer Control Plane ("What Runs Next?")

To prevent split-brain control flow, scheduling decisions follow a strict, unidirectional authority chain:

```text
                    ┌────────────────────────┐
                    │   1. DAG Graph Builder │ "What is legally possible?"
                    └───────────┬────────────┘
                                │ (Legal Dependency & Readiness Graph)
                                ▼
                    ┌────────────────────────┐
                    │   2. Stage Planner     │ "Which stage runs next?"
                    └───────────┬────────────┘
                                │ (Active Stage Scope & Budget Allocation)
                                ▼
                    ┌────────────────────────┐
                    │   3. Priority Engine   │ "Which work candidate deserves execution?"
                    └───────────┬────────────┘
                                │ (Ordered Candidate Queue: candidate -> score)
                                ▼
                    ┌────────────────────────┐
                    │ 4. Speculative         │ "What exact request contract are we asking to run?"
                    │    Dispatcher          │
                    └───────────┬────────────┘
                                │ (ExecutionRequest with Authorization Context)
                                ▼
                    ┌────────────────────────┐
                    │ 5. Authorization &     │ "Is this request cryptographically authorized & budgeted?"
                    │    Resource Gate       │
                    └───────────┬────────────┘
                                │ (Signed AuthorizedExecutionTicket)
                                ▼
                    ┌────────────────────────┐
                    │ 6. Actor Scheduler     │ "Where and when does this run?"
                    └───────────┬────────────┘
                                │ (Placement: LEASED, DEFERRED, REJECTED, CIRCUIT_OPEN)
                                ▼
                    ┌────────────────────────┐
                    │ 7. Executor / Sandbox  │ "DO IT (Stateless execution inside isolated sandbox)"
                    └───────────┬────────────┘
                                │
                                ▼
                         ExecutionResult
                                │
                   ┌────────────┼────────────┐
                   ▼            ▼            ▼
                Findings   StateDeltas     Logs
                                │
                                ▼
                    ┌────────────────────────┐
                    │    State Authority     │ (Single-source-of-truth State Merge Engine)
                    └───────────┬────────────┘
                           ┌────┴────┐
                           ▼         ▼
                          WAL       CRDT (LWW-Set / HLC)
                                     │
                                     ▼
                               Actor Gossip
```

---

### 2. State Authority vs. Worker Separation

- **Workers Produce; State Authority Commits**: Execution Workers never directly mutate the Frontier CRDTs, WAL, or persistent stores. Workers return an immutable `ExecutionResult` containing `state_deltas`.
- **Single State Authority**: The `State Authority` validates received deltas, verifies sequence versions, appends to the Write-Ahead Log (WAL), and performs the deterministic CRDT merge ($O(1)$ space with Hybrid Logical Clocks).

```text
Worker ──────► ExecutionResult(state_deltas) ──────► State Authority ──────► WAL & CRDT Store
```

---

### 3. Authorization & Resource Gate with Replay Resistance

- **Speculative Dispatcher Role**: The Dispatcher translates ranked work into an immutable `ExecutionRequest` carrying context (`ScopeToken`, `TenantID`, `Capabilities`, `Deadline`, `ResourceLimits`, `execution_id`, `job_id`). It does **not** grant execution authority.
- **Authorization Gate Role** (`src/decision/authorization.py`):
  - Normalizes evasive URL paths (unquoting, matrix stripping, slash collapsing, POSIX directory traversal resolution).
  - Validates domain wildcards (`*.example.com`) and CIDR subnets (`10.0.0.0/8`).
  - Issues an HMAC-SHA256 signed `AuthorizedExecutionTicket` with a unique `nonce`.
  - Atomically marks tickets consumed upon single-use to prevent execution replay during ticket lifetime.

---

### 4. Candidate Lifecycle: Peeking, Leasing, and Acknowledgement

To prevent candidate loss and redundant duplicate dispatches:
```text
AVAILABLE ──(lease_batch)──► IN-FLIGHT (Lease Active) ──(ack_batch)──► COMPLETED
                                      │
                         (release_batch / TTL Expiry)
                                      │
                                      ▼
                                  AVAILABLE
```
- `lease_batch(limit, ttl)`: Leases top candidates, hiding them from concurrent peek/dispatch cycles.
- `ack_batch(urls)`: Marks leased candidates as scanned upon verified `ExecutionResult` ingestion by the State Authority.
- `release_batch(urls)`: Returns leased candidates to the available queue on downstream failure.

---

### 5. Actor Scheduler Placement & Retry Ownership

- **Placement Semantics**:
  - `LEASED`: Request placed onto available worker slot.
  - `PLACEMENT_DEFERRED`: Concurrency cap reached; request held in scheduler queue.
  - `PLACEMENT_REJECTED`: Policy, budget, or scope constraint exceeded.
  - `WORKER_UNAVAILABLE`: Worker host crashed or unreachable.
  - `CIRCUIT_OPEN`: Target or tool tripped circuit breaker; request fast-failed.
- **Retry Ownership**:
  - `ActorScheduler` is strictly a placement engine and does not loop internally.
  - The **Stage Orchestrator / Dispatcher** owns the retry policy and backoff queue when `PLACEMENT_DEFERRED` is returned.

---

### 6. Atomic Budget Controller & Reservation Accounting

- Stage budgets are governed by `HuntBudgetEnforcer` (`src/decision/hunt_budget.py`).
- **Reservation Accounting**:
  - `available = max_requests - (reserved + consumed)`
  - `reserve_requests(count)`: Mutex-guarded atomic quota reservation before worker dispatch.
  - `commit_requests(count)`: Converts reserved quota to consumed upon `ExecutionResult` ingestion.
  - `release_requests(count)`: Releases unneeded reservations back to the pool on failure.

---

### 7. Cognitive Vulnerability Analysis & Validation

- **Differential State Probing**: `src/analysis/intelligence/differential_prober.py` compares responses across differing authentication roles and tenant boundaries using normalized Levenshtein distance, automatically discovering Insecure Direct Object References (IDOR) and Broken Access Controls (BAC).
- **PoC Validation Sandbox**: Dynamic Python plugins use a JSON child-process boundary with AST pre-validation (`src/core/plugins/sandbox.py`), preventing lateral execution on the host runner.
- **Adaptive Closed-Loop Learning**: Operator triage signals update the false-positive rules matrix (`src/learning/fp_rules.py`) and adjust severity calibration weights, suppressing duplicate alerts across subsequent scan runs.

---

## 🎨 Real-Time Operator Cockpit & Dashboard

The frontend serves as an interactive command and telemetry console:
- **React 19 + Tailwind CSS 4**: Modern component architecture utilizing Zustand stores (`useJobStore`, `useFindingsStore`, `useMeshStore`) with sub-millisecond state updates.
- **Virtualization**: `react-virtuoso` renders high-volume log streams (100,000+ entries) and extensive finding catalogs at a smooth 60 FPS.
- **3D Threat Cockpit**: React Three Fiber + Three.js (`InstancedMesh`) visualizes complex multi-hop attack graphs with real-time node state color coding.
- **Interactive Request Replay**: In-browser HTTP request/response inspection and differential replay tool for instant manual vulnerability confirmation.

---

## 🔒 Governance, Multi-Tenancy & Integrity

- **Tenant Isolation**: Thread-safe and async-safe context propagation via `TenantContext` (`contextvars`) ensures that all database queries, Redis keys, pub/sub channels, and file outputs are isolated per tenant ID.
- **Supply-Chain Integrity**: Nuclei templates and scanning rules are validated at startup against cryptographic signatures and SHA-256 baseline manifests.
- **Contract Enforcement**: FastAPI endpoints strictly enforce Pydantic v2 validation models on the backend and Zod schema contracts on the frontend.
