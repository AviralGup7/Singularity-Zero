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
```

### 2. State Authority & Transactional WAL Settlement Intent Boundary

- **Workers Produce; State Authority Commits to WAL**: Execution Workers never directly mutate the Frontier CRDTs, WAL, or persistent stores. Workers return an immutable `ExecutionResult`.
- **Settlement Coordinator (`SettlementCoordinator`)**: The single production settlement path responsible for:
  1. **Constructing `SettlementIntent`**: Validates identities (`execution_id`, `lease_id`, `candidate_id`) and creates an immutable `SettlementIntent` containing the atomic settlement decision (state deltas, budget action, and lease action).
  2. **Authoritative WAL Commit**: Calls `StateAuthority.append_settlement_intent()`, which writes the entire `SettlementIntent` as a single atomic record to the Write-Ahead Log (WAL). This WAL write is the single point of truth.
  3. **Idempotent Projections**: Forwards the durable intent to independent projection engines (`StateProjection`, `BudgetProjection`, `LeaseProjection`), which advance their independent cursors.
  4. **Crash Recovery**: If the process restarts or projections lag, `SettlementCoordinator.replay_projections(wal)` reads from the WAL cursor and catches up each projection independently and idempotently.
- **Single State Authority (`StateAuthority`)**: Validates schema, appends settlement envelopes to the Write-Ahead Log (WAL), verifies sequence versions, performs deduplication on `execution_id`, and executes deterministic CRDT merges. (Hybrid Logical Clocks provide $O(1)$ space clock metadata per comparison, with $O(N)$ LWW-Set total element storage).

```text
Worker ──► ExecutionResult ──► SettlementCoordinator
                                     │
                             (SettlementIntent)
                                     │
                                     ▼
                          StateAuthority.append()
                                     │
                                     ▼
                                ┌─────────┐
                                │   WAL   │ (Single Authoritative Boundary)
                                └────┬────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
    StateProjection           BudgetProjection           LeaseProjection
    (NeuralState CRDT)       (HuntBudgetEnforcer)       (PriorityQueue Lease)
       [Cursor A]                 [Cursor B]                 [Cursor C]
```

---

### 3. Authorization & Resource Gate with Replay Resistance

- **Speculative Dispatcher Role**: The Dispatcher translates ranked work into an immutable `ExecutionRequest` carrying context (`ScopeToken`, `TenantID`, `Capabilities`, `Deadline`, `ResourceLimits`, `execution_id`, `job_id`, `candidate_id`, `lease_id`, `policy_version`). It does **not** grant execution authority.
- **Authorization Gate Role** (`src/decision/authorization.py`):
  - Normalizes evasive URL paths (unquoting, matrix stripping, slash collapsing, POSIX directory traversal resolution).
  - Validates domain wildcards (`*.example.com`) and CIDR subnets (`10.0.0.0/8`).
  - Reserves request quota atomically from `HuntBudgetEnforcer.reserve_requests()`.
  - Issues an HMAC-SHA256 signed `AuthorizedExecutionTicket` with a unique `nonce`.
  - Atomically marks tickets consumed upon single-use to prevent execution replay during ticket lifetime.
- **Worker Security**: `ExecutionRequestWorker.execute(ticket)` strictly requires an `AuthorizedExecutionTicket`. Unauthenticated raw `ExecutionRequest` instances are rejected with `outcome="REJECTED"`.

---

### 4. Candidate Identity & Lease Lifecycle

To prevent candidate loss, race conditions, and redundant duplicate dispatches:
```text
AVAILABLE ──(lease_batch)──► IN-FLIGHT (CandidateLease) ──(ack_batch)──► COMPLETED
                                       │
                          (release_batch / TTL Expiry)
                                       │
                                       ▼
                                   AVAILABLE
```
- `lease_batch(limit, ttl, worker_id, execution_id)`: Generates a cryptographically unique `lease_id` and binds `candidate_id`, returning a `CandidateLease`.
- `ack_batch([lease])`: Verifies that `target.lease_id == lease.lease_id` and `target.lease_worker_id == lease.worker_id`. Stale or expired lease acknowledgements are safely rejected.
- `release_batch([lease])`: Returns leased candidates to the available queue on downstream failure.

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

### 6. Atomic Budget Controller & Reservation Lifecycle

- Stage budgets are governed by `HuntBudgetEnforcer` (`src/decision/hunt_budget.py`).
- **Reservation Accounting**:
  - `available = max_requests - (reserved + consumed)`
  - `reserve_requests(count)`: Mutex-guarded atomic quota reservation at the Authorization Gate.
  - `commit_requests(count)`: Converts reserved quota to consumed upon `SettlementCoordinator.settle()`.
  - `release_requests(count)`: Releases unneeded reservations back to the pool on rejection, failure, or timeout.
  - Legacy unreserved `record_request()` calls have been eliminated from production execution loops.

---

### 7. Immutable Versioned Policy & Decision Provenance

- **VersionedPolicy (`src/learning/versioned_policy.py`)**: Immutable, versioned policy container specifying `target_boosts`, `target_suppressions`, and tool configuration parameters.
- **Priority Engine Consumption**: `CorrelationPriorityQueue.apply_versioned_policy(policy)` directly consumes the policy to dynamically boost or suppress candidates.
- **Provenance Tracking**: `policy_version` is bound to `ExecutionRequest.policy_version` and propagated to `ExecutionResult.policy_version` for auditability.

---

### 8. Cognitive Vulnerability Analysis & Validation

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
