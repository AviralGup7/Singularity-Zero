# Project Architecture: Cyber Security Test Pipeline

## Implementation Status & Engineering Ground Truth

This document outlines the architecture, distributed execution model, resilience mechanisms, and cognitive analysis components of the Cyber Security Test Pipeline. The table below delineates production-shipped components from research and prototype systems:

| Subsystem / Capability | Current Status | Code Location |
|---|---|---|
| **Authoritative State Authority & Settlement** | **Production** — Single authoritative WAL commit point, 5-stage untrusted claim validation, epoch fencing, and independent projection engines (`StateProjection`, `BudgetProjection`, `LeaseProjection`, `FindingsProjection`) | `src/core/frontier/state_authority.py` |
| **Command Envelopes & Event Upcasters** | **Production** — Strongly-typed `CommandEnvelope`, `EventEnvelope`, causation/correlation ID tracking, aggregate versioning, and `SchemaUpcasterRegistry` for backward-compatible replay | `src/core/contracts/command_envelope.py` |
| **Partitioned Single-Writer Router** | **Production** — Consistent hashing `hash(target) % N` to single logical partition leaders with monotonic epoch counters and zombie worker claim rejection | `src/core/frontier/partition_authority.py` |
| **Canonical Target Identity Engine** | **Production** — Deterministic IDNA Punycode normalization, POSIX traversal resolution, query sorting, default port stripping, and DNS snapshot pinning | `src/core/contracts/canonical_target.py` |
| **DAG Pipeline Orchestrator** | **Production** — Async DAG builder, actor scheduler, stage lifecycle, speculative dispatch, checkpoint persistence, and resume flows | `src/pipeline/services/pipeline_orchestrator/`, `src/pipeline/engine.py` |
| **Resilience & Circuit Breaking** | **Production** — tool breaker is `src/pipeline/services/circuit_breaker.py`; Retry-After parser is `src/resilience/retry_after.py` | `src/pipeline/services/circuit_breaker.py`, `src/resilience/retry_after.py` |
| **Unified Hierarchical Cache** | **Production** — In-memory LRU + SQLite/Redis tiered cache with single-flight request coalescing and stale-while-revalidate | `src/pipeline/unified_cache/`, `src/cache/` |
| **Frontier State & CRDT Engine** | **Production** — LWW-Set CRDTs keyed by Hybrid Logical Clocks (HLC) for eventually consistent discovery knowledge | `src/frontier/`, `src/core/frontier/state.py` |
| **Out-of-Band ML Policy Governance** | **Production** — `PolicyGovernanceGate` with shadow evaluation against feedback runaway, canary promotion, and atomic rollback to `parent_policy_id` | `src/learning/policy_governance.py`, `src/learning/versioned_policy.py` |
| **Prioritized QoS Telemetry Broker** | **Production** — 5-tier QoS backpressure router (P0 Control, P1 Lifecycle, P2 Coalesced Findings, P3 Telemetry Aggregates, P4 Debug Shedding) | `src/realtime/prioritized_broker.py` |
| **Deterministic Replay Engine** | **Production** — Pure sequential WAL log replay from arbitrary offsets for exact projection state reconstruction and post-replay invariant verification | `src/core/frontier/replay_engine.py` |
| **Tamper-Evident Audit Ledger** | **Production** — Cryptographic HMAC-SHA256 chained audit trail for administrative, authentication, and scan events | `src/auth/audit.py`, `src/console/audit.py` |
| **Active & Passive Analyzers** | **Production** — Multi-stage detectors for SQLi, XSS, SSRF, IDOR/BAC, JWT forgery, CSP bypass, and HTTP/2 smuggling | `src/analysis/active/`, `src/analysis/passive/` |
| **Cognitive Differential Prober & IDOR Analysis** | **Production** — Cross-role normalized Levenshtein diffing for automatic Broken Object Level Authorization discovery | `src/analysis/intelligence/differential_prober.py` |
| **Process / WASM Isolation Sandbox** | **Production** — OS-native resource caging (memory limits, CPU timeout, env scrubbing) and AST plugin verification | `src/sandbox/process_sandbox.py`, `src/core/plugins/sandbox.py` |
| **3D Threat Cockpit & Real-time Console** | **Production** — React 19 + Three.js instanced attack graph rendering, Zustand stores, virtualized log streams, and WebSockets | `frontend/src/`, `src/websocket_server/` |
| **Distributed Actor Mesh** | **Production (Single-node & P2P)** — Pykka/Asyncio workers with authenticated AES-256-GCM SWIM gossip discovery and shard balancing | `src/mesh/`, `src/infrastructure/mesh/` |
| **Algorithmic Multi-Hop Attack Path Engine** | **Production** — Graph engine synthesizing Dijkstra shortest attack paths to critical assets | `src/intelligence/graph/attack_graph.py` |
| **Formal Execution Contracts** | **Production** — Immutable `ExecutionRequest` / `RawExecutionClaim` / `ExecutionResultContract` handoff, cryptographic `ScopeToken` authorization, and stateless worker execution | `src/decision/models.py`, `src/decision/authorization.py`, `src/execution/request_executor.py`, `src/core/contracts/execution_request.py` |

---

## 🏛️ The 10 Laws of Distributed Correctness

1. **One Authoritative State Machine Owns Correctness**: The state machine alone validates invariants and decides transitions. Projections, caches, CRDTs, and transport layers are derived, eventually consistent, and reconstructible.
2. **The Durable Log is the Single Point of Truth**: Every authoritative transition is recorded as an immutable, strongly-typed event in the Write-Ahead Log (WAL).
3. **Projections Can Be Deleted and Rebuilt**: Projections only reconstruct already-committed state and are never allowed to decide whether an operation is valid.
4. **Caches Can Be Evicted Without Affecting Correctness**: Caches serve strictly for performance optimization and can be flushed cold at any time.
5. **CRDTs Are Used Exclusively for Eventually Consistent Knowledge**: Frontier discovery, observed assets, and peer gossip use CRDTs; core coordination (budget, leases, quota, claims) uses strongly consistent state machines.
6. **Every Lease Carries a Fencing Epoch & Token**: Operations with $\text{epoch} < \text{current\_epoch}$ are strictly rejected with zero side effects.
7. **Every Execution References an Immutable Policy Version**: Policies carry full lineage metadata (`policy_id`, `parent_policy_id`, `signature`, `schema_version`).
8. **Workers are Untrusted and Emit Claims**: Workers submit `RawExecutionClaim` envelopes that pass 5-stage verification (signatures, epoch fencing, canonical scope, proof hashes, quota) before settlement.
9. **ML Optimizes Decisions But Cannot Grant Authority**: Out-of-band active learning is governed by shadow-canary evaluation and cannot bypass authorization gates or positive feedback guardrails.
10. **Every Distributed State Transition is Replayable and Causally Traceable**: Causation IDs, correlation IDs, and deterministic log replay ensure complete reproducibility.

---

## 🛡️ Core System Invariants

### 1. Budget Invariant
$$\text{committed\_requests} + \text{reserved\_requests} + \text{requested\_quota} \le \text{budget\_limit}$$

### 2. Lease Invariant
$$\forall \text{ candidate } c: \quad \text{active\_leases}(c) \le 1$$

### 3. Fencing Invariant
$$\text{claim}.\text{epoch} < \text{active\_lease}.\text{epoch} \implies \text{REJECT (Zombie claim)}$$

### 4. Authorization Invariant
$$\text{execution\_dispatch} \implies \text{Valid, unconsumed, HMAC-signed } \text{AuthorizedExecutionTicket}$$

### 5. Settlement Invariant
$$\text{settlement\_id is committed to WAL and processed by projections exactly once}$$

### 6. Deterministic Replay Invariant
$$\text{replay}(\text{WAL}[0 \dots N]) \equiv \text{expected\_state}_N$$

---

## 🏛️ The 7-Layer Control Plane ("What Runs Next?")

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
                                │ (Signed AuthorizedExecutionTicket + Pinned Canonical Target)
                                ▼
                    ┌────────────────────────┐
                    │ 6. Actor Scheduler     │ "Where and when does this run?"
                    └───────────┬────────────┘
                                │ (Placement: LEASED, DEFERRED, REJECTED, CIRCUIT_OPEN)
                                ▼
                    ┌────────────────────────┐
                    │ 7. Executor / Sandbox  │ "DO IT (Stateless execution inside isolated sandbox)"
                    └───────────┬────────────┘
                                │ (Untrusted RawExecutionClaim)
                                ▼
                    ┌────────────────────────┐
                    │ Settlement Coordinator │ "Verify ticket, fencing epoch, proof hashes & commit"
                    └────────────────────────┘
```

---

## 🔄 Core Subsystems & Lifecycles

### 1. Partitioned Single-Writer Architecture (`src/core/frontier/partition_authority.py`)
To prevent cross-region split-brain, targets are routed to logical partition leaders via deterministic consistent hashing:
$$\text{partition\_id} = \text{hash}(\text{canonical\_identity}) \pmod N$$

- **Monotonic Epoch Counter**: Each partition manages a strictly increasing `epoch` counter.
- **Failover / Expiry Invalidation**: Whenever a lease expires or a partition leader fails over, the epoch increments.
- **Zombie Worker Elimination**: Late responses from zombie workers carrying stale tokens (`claim.epoch < active.epoch`) are rejected without touching persistent state.

---

### 2. Deterministic Canonical Target Identity (`src/core/contracts/canonical_target.py`)
Incoming target URLs undergo multi-stage normalization before authorization and routing:
1. **Scheme & Default Port Normalization**: Schemes are lowercased; default ports (`80` for HTTP, `443` for HTTPS) are elided.
2. **Hostname IDNA Normalization**: Hostnames are converted to ASCII Punycode (`xn--...`), lowercased, and stripped of trailing FQDN dots.
3. **POSIX Path Normalization**: Matrix parameters (`;param=val`) are stripped, consecutive slashes are collapsed, and `/../` path traversals are resolved.
4. **Query Parameter Sorting**: Query parameters are sorted alphabetically by key and value; fragments (`#...`) are stripped.
5. **DNS Snapshot Pinning**: DNS resolution snapshots are pinned at authorization time to eliminate Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding and SSRF bypasses.

---

### 3. Command Envelopes & Schema Upcasters (`src/core/contracts/command_envelope.py`)
State transitions are expressed as strongly-typed command and event envelopes:
- **`CommandEnvelope`**: Encapsulates intent with `command_id`, `command_type`, `correlation_id`, `causation_id`, `tenant_id`, and `schema_version`.
- **`EventEnvelope`**: Encapsulates committed facts with `event_id`, `event_type`, monotonic `log_offset`, and payload.
- **`SchemaUpcasterRegistry` (`GLOBAL_UPCASTER_REGISTRY`)**: Transforms historical event payloads progressively across schema version increments ($V_1 \to V_2 \to \dots \to V_N$) during deterministic log replay.

---

### 4. State Authority & Transactional WAL Settlement Intent Boundary (`src/core/frontier/state_authority.py`)

- **Workers Produce Claims; State Authority Commits to WAL**: Execution Workers never directly mutate the Frontier CRDTs, WAL, or persistent stores. Workers return an untrusted `RawExecutionClaim`.
- **Settlement Coordinator (`SettlementCoordinator`)**: The single production settlement path responsible for:
  1. **5-Stage Verification Gate**:
     - *Gate 1: Ticket & Nonce Verification*: Single-use HMAC token check preventing execution replay.
     - *Gate 2: Partition Epoch Fencing*: Validates `claim.epoch == current_partition_epoch`.
     - *Gate 3: Canonical Scope Compliance*: Verifies that normalized target remains within permitted wildcards and CIDRs.
     - *Gate 4: Evidence Proof Hashing*: Validates SHA-256 evidence hashes.
     - *Gate 5: Resource Accounting*: Validates execution duration and action count against resource quotas.
  2. **Authoritative WAL Commit**: Constructs an atomic `SettlementIntent` and appends it to the Write-Ahead Log (`StateAuthority.append_settlement_intent()`).
  3. **Idempotent Projections**: Forwards the committed intent to independent projection engines:
     - `StateProjection`: Applies state deltas to `NeuralState` CRDTs.
     - `BudgetProjection`: Commits or releases request quotas in `HuntBudgetEnforcer`.
     - `LeaseProjection`: Acknowledges (`ACK`) or releases (`RELEASE`) candidate leases in `CorrelationPriorityQueue`.
     - `FindingsProjection`: Ingests and deduplicates security findings.
  4. **Crash Recovery**: If the process restarts, `SettlementCoordinator.replay_projections(wal)` reads from the durable WAL cursor and catches up each projection independently and idempotently.

```text
Worker ──► RawExecutionClaim ──► SettlementCoordinator (5-Stage Gate)
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
            ┌──────────────────────────┼──────────────────────────┬──────────────────────────┐
            ▼                          ▼                          ▼                          ▼
      StateProjection           BudgetProjection           LeaseProjection           FindingsProjection
      (NeuralState CRDT)       (HuntBudgetEnforcer)       (PriorityQueue Lease)      (Findings Catalog)
         [Cursor A]                 [Cursor B]                 [Cursor C]                 [Cursor D]
```

---

### 5. Authorization & Resource Gate with Replay Resistance (`src/decision/authorization.py`)

- **Speculative Dispatcher Role**: The Dispatcher translates ranked work into an immutable `ExecutionRequest` carrying context (`ScopeToken`, `TenantID`, `Capabilities`, `Deadline`, `ResourceLimits`, `execution_id`, `job_id`, `candidate_id`, `lease_id`, `policy_version`). It does **not** grant execution authority.
- **Authorization Gate Role** (`src/decision/authorization.py`):
  - Normalizes evasive URL paths (unquoting, matrix stripping, slash collapsing, POSIX directory traversal resolution).
  - Validates domain wildcards (`*.example.com`) and CIDR subnets (`10.0.0.0/8`).
  - Reserves request quota atomically from `HuntBudgetEnforcer.reserve_requests()`.
  - Issues an HMAC-SHA256 signed `AuthorizedExecutionTicket` with a unique single-use `nonce`.
  - Atomically marks tickets consumed upon single-use to prevent execution replay during ticket lifetime.
- **Worker Security**: `ExecutionRequestWorker.execute(ticket)` strictly requires an `AuthorizedExecutionTicket`. Unauthenticated raw `ExecutionRequest` instances are rejected with `outcome="REJECTED"`.

---

### 6. Candidate Identity & Lease Lifecycle (`src/decision/priority_queue.py`)

To prevent candidate loss, race conditions, and duplicate dispatches:
```text
AVAILABLE ──(lease_batch)──► IN-FLIGHT (CandidateLease) ──(ack_batch)──► COMPLETED
                                       │
                          (release_batch / TTL Expiry)
                                       │
                                       ▼
                                   AVAILABLE
```
- `lease_batch(limit, ttl, worker_id, execution_id)`: Generates a cryptographically unique `lease_id`, binds `candidate_id`, and returns a `CandidateLease`.
- `ack_batch([lease])`: Verifies that `target.lease_id == lease.lease_id` and `target.lease_worker_id == lease.worker_id`. Stale or expired lease acknowledgements are safely rejected.
- `release_batch([lease])`: Returns leased candidates to the available queue on downstream failure.

---

### 7. Actor Scheduler Placement & Retry Ownership (`src/pipeline/services/pipeline_orchestrator/scheduler.py`)

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

### 8. Atomic Budget Controller & Reservation Lifecycle (`src/decision/hunt_budget.py`)

- Stage budgets are governed by `HuntBudgetEnforcer` (`src/decision/hunt_budget.py`).
- **Reservation Accounting**:
  - $\text{available} = \text{max\_requests} - (\text{reserved} + \text{consumed})$
  - `reserve_requests(count)`: Mutex-guarded atomic quota reservation at the Authorization Gate.
  - `commit_requests(count)`: Converts reserved quota to consumed upon `SettlementCoordinator.settle()`.
  - `release_requests(count)`: Releases unneeded reservations back to the pool on rejection, failure, or timeout.

---

### 9. Out-of-Band ML Policy Governance & Canary Gate (`src/learning/policy_governance.py`)

The active learning engine operates outside the execution correctness loop:
- **VersionedPolicy (`src/learning/versioned_policy.py`)**: Immutable, versioned policy container specifying `target_boosts`, `target_suppressions`, and tool configuration parameters with `parent_policy_id` lineage.
- **PolicyGovernanceGate (`src/learning/policy_governance.py`)**:
  - *Shadow Evaluation*: Evaluates candidate policies against historical finding matrices, preventing positive feedback runaway (excessive target boosts $> 5.0\times$ or total candidate suppressions $> 80\%$).
  - *Canary Rollout*: Stages policy deployment across worker canary subsets.
  - *Atomic Rollback*: Instantly reverts active policy to `parent_policy_id` upon telemetry anomalies.
- **Priority Engine Consumption**: `CorrelationPriorityQueue.apply_versioned_policy(policy)` directly consumes the policy to dynamically prioritize candidates.
- **Provenance Tracking**: `policy_version` is bound to `ExecutionRequest.policy_version` and propagated to `RawExecutionClaim` for complete auditability.

---

### 10. Multi-Tier Prioritized QoS Telemetry Broker (`src/realtime/prioritized_broker.py`)

Telemetry and real-time events are routed through a 5-lane QoS broker:
- **P0 (Emergency & Control)**: Unbounded FIFO queue, strict delivery, never dropped.
- **P1 (Execution Lifecycle)**: Reliable delivery, fixed capacity queue.
- **P2 (Vulnerability Findings)**: Deduplicated and coalesced by finding key.
- **P3 (Telemetry & Metrics)**: 1-second sliding window aggregation.
- **P4 (Debug & Raw Logs)**: Sampled or dropped upon queue saturation.

---

### 11. Deterministic Replay Engine (`src/core/frontier/replay_engine.py`)

Enables exact state reconstruction from arbitrary log offsets:
- Sequentially executes committed WAL log entries without external clock or random number dependencies.
- Applies schema upcasters from `GLOBAL_UPCASTER_REGISTRY`.
- Reconstructs all projection states (`StateProjection`, `BudgetProjection`, `LeaseProjection`, `FindingsProjection`).
- Verifies post-replay invariants and yields `ReplaySummary`.

---

### 12. Cognitive Vulnerability Analysis & Native OS Sandbox

- **Differential State Probing**: `src/analysis/intelligence/differential_prober.py` compares responses across differing authentication roles and tenant boundaries using normalized Levenshtein distance, automatically discovering Insecure Direct Object References (IDOR) and Broken Access Controls (BAC).
- **Native OS Process Sandbox (`src/sandbox/process_sandbox.py`)**: Exploit scripts and external tools execute inside an OS-native resource cage enforcing hard memory limits (`max_memory_mb`), CPU timeouts (`timeout_seconds`), and strict credential environment scrubbing (`AWS_`, `DATABASE_URL`, `TOKEN`).
- **Adaptive Closed-Loop Learning**: Operator triage signals update the false-positive rules matrix (`src/learning/fp_rules.py`) and adjust severity calibration weights, suppressing duplicate alerts across subsequent scan runs.

---

### 13. Zero-Trust Mesh & AES-256-GCM Payload Encryption

- **P2P Gossip Security (`src/infrastructure/mesh/gossip/serializer.py`)**:
  - **Confidentiality**: UDP gossip message payloads are encrypted using authenticated **AES-256-GCM** with 96-bit random nonces derived from `MESH_SECRET`. Discovered targets, IP assets, and vulnerability metrics are never broadcast in plaintext.
  - **Integrity & Authenticity**: Envelopes are signed via **HMAC-SHA256**, ensuring tampered or replayed packets are discarded before deserialization.

---

### 14. Algorithmic Multi-Hop Attack Path & Exploit Chain Engine

- **AttackGraphEngine (`src/intelligence/graph/attack_graph.py`)**:
  - Models entities as `GraphNode` (`asset`, `finding`, `credential`, `impact`) and relationships as `GraphEdge` (`EXPOSES`, `AUTHENTICATES`, `LEADS_TO`, `ESCALATES_TO`).
  - Implements **Dijkstra's shortest-path algorithm** to synthesize complete lateral attack chains (`AttackChain`) from initial entry points to critical compromise targets.
  - Feeds discovered exploit chains directly into `PolicyAutoDispatcher` to dynamically boost priority for critical entry points in `CorrelationPriorityQueue`.

---

### 15. Cross-Region WAL Replication Relay

- **WALReplicationRelay (`src/infrastructure/frontier/replication.py`)**:
  - Asynchronously fans out settlement intents and deltas across regional Redis streams (`cyber:wal:{run_id}`).
  - Automatically pulls and reconciles remote peer deltas on link recovery using idempotent execution tracking.

---

### 16. Dynamic Adaptive Rate Limiter (AIMD Congestion Control)

- **AdaptiveRateLimiter (`src/resilience/adaptive_rate_limiter.py`)**:
  - Additive-Increase / Multiplicative-Decrease congestion control per target domain.
  - Throttles concurrent worker slots and triggers exponential backoff upon encountering HTTP 429/503 responses, preventing target exhaustion.

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
