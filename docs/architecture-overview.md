# Architecture Overview

This document provides a **non-marketing, engineering-focused** map of the Cyber Security Test Pipeline. It details the structural design patterns, data flow mechanisms, and modules that implement them across the codebase.

---

## High-Level Topology

```text
┌─────────────────────────┐       HTTP REST / WebSocket        ┌───────────────────────────────────┐
│   React 19 Dashboard    │ ◀────────────────────────────────▶ │  FastAPI Dashboard Backend        │
│   (frontend/src/)       │                                    │  (src/dashboard/fastapi/)         │
└─────────────────────────┘                                    └─────────────────┬─────────────────┘
                                                                                 │ Enqueue / Control
                                                                                 ▼
                         ┌─────────────────────────────────────────────────────────────────────────┐
                         │   Distributed Pipeline Orchestrator (src/pipeline/)                     │
                         │   ├── DAG Graph Builder & Actor Scheduler                              │
                         │   ├── Lifecycle: Recon → Probing → Exploitation → Learning → Reporting  │
                         │   ├── Circuit Breaker & Retry-After Rate Limiting (src/resilience/)     │
                         │   └── Self-Healing & Dynamic Correction Engine                          │
                         └───────────────────┬─────────────────────────────────┬───────────────────┘
                                             │                                 │
                         ┌───────────────────▼───────────────────┐             │
                         │   Recon & Analysis Engines            │             │ State & Sync
                         │   ├── Recon Collectors (src/recon/)   │             │
                         │   ├── Active Analyzers (src/analysis/)│             ▼
                         │   ├── Fuzzing & Mutation (src/fuzzing)│ ┌───────────────────────────────┐
                         │   └── Exploit Sandbox (src/sandbox/)  │ │ State & Persistence Planes    │
                         └───────────────────┬───────────────────┘ │ ├── Frontier CRDTs (src/frontier)│
                                             │                     │ ├── Unified Cache (src/cache/) │
                                             ▼                     │ ├── Authoritative Log (WAL)   │
                         ┌───────────────────────────────────────┐ │ └── Actor Mesh (src/mesh/)    │
                         │   Enrichment & Reporting Sinks        │ └───────────────────────────────┘
                         │   ├── ML Policy Governance & Learning │
                         │   │   (src/learning/, src/intel/)     │
                         │   └── Report Attestation (src/reporting/) │
                         └───────────────────────────────────────┘
```

---

## Subsystems & Implementation Map

| Subsystem | Location | Technical Implementation & Responsibilities |
|---|---|---|
| **Partitioned Raft FSM & Replicated Log** | `src/core/frontier/raft_fsm.py`, `src/core/frontier/replicated_log.py` | Partitioned in-memory Raft FSM engine ($L_0$ Replicated Log $\rightarrow$ $L_1$ Deterministic FSM) with multi-replica identical application, deterministic `CommandResult`, and leader-signed certified receipts (`CommandReceipt`). |
| **Global Coordination (`P-0000`) & Run Sagas** | `src/core/frontier/global_coordination.py`, `src/core/frontier/run_saga.py` | `GlobalBudgetAggregate` (exact integer conservation: $\text{Total} = \text{Consumed} + \text{Outstanding} + \text{Available}$, `expire_sublease` timeout reclaim), `PlacementAuthority` (5-stage fenced migration), and `DurableRunSagaEngine`. |
| **Authoritative State & Settlement** | `src/core/frontier/state_authority.py`, `src/core/checkpoint/` | Centralized `StateAuthority` (WAL append, schema validation, deduplication), Level 3 `CheckpointState` projection validation (`verify_checkpoint_against_fsm`), and `SettlementCoordinator` (5-stage claim validation, epoch fencing, and independent projection engines). |
| **Command Envelopes & Event Upcasting** | `src/core/contracts/command_envelope.py` | Strongly-typed `CommandEnvelope`, Model B `CommittedEntry` carrying deterministic event envelopes ($\text{event\_id} = \text{SHA256}(\text{partition} \mathbin{\Vert} \text{index} \mathbin{\Vert} \text{seq})$), and `SchemaUpcasterRegistry`. |
| **Canonical Target & State Encoding** | `src/core/contracts/canonical_target.py` | Deterministic target normalization and `canonical_state_encode` (maps sorted, sets sorted, lists preserved, exact integers, float rejection) with dual snapshot hash checking. |
| **Projection Vector Watermarks & Cold Rebuild** | `src/core/frontier/projection_stream.py` | Level 3 materialized read models with `ProjectionCheckpointVector` tracking `(partition, term, index, hash)`, gap detection ($K > \text{last} + 1 \Rightarrow \text{GAP\_DETECTED}$), and parallel cold rebuild from offset 0. |
| **Formal Invariants Verification** | `src/core/frontier/invariant_checker.py`, `tests/unit/test_formal_invariants.py` | 9-point formal invariant test suite (`INVARIANT-001`–`INVARIANT-009`) and machine-checkable audit runner evaluating all 16 target system invariants ($I_1$–$I_{16}$) before opening partitions to traffic. |
| **Reconnaissance Engine** | `src/recon/` | Multi-source asynchronous OSINT collectors (Wayback, CommonCrawl, AlienVault, OTX, Shodan), DNS wildcard elimination, JS AST route extraction, and cloud asset mapping. |
| **Active & Passive Analysis** | `src/analysis/` | Heuristic vulnerability detectors (SQLi, XSS, IDOR/BAC, JWT forgery, HTTP/2 smuggling, CSP bypass) emitting structured `AnalyzerResult` events. |
| **Exploitation & Sandboxing** | `src/exploitation/`, `src/sandbox/`, `src/execution/` | End-to-end exploit validation harnesses. PoCs execute inside OS-level process cages (`ProcessSandbox`) with credential stripping and POSIX limits; WASM runtime is feature-flagged. |
| **Pipeline DAG Orchestrator** | `src/pipeline/`, `src/pipeline/services/pipeline_orchestrator/` | Asynchronous DAG executor (`GraphBuilder`, `ActorScheduler`, `Orchestrator`) handling task dependency resolution, speculative dispatch, checkpoint persistence, and resume flows. |
| **Resilience & Circuit Breaking** | `src/resilience/` | 3-state Circuit Breaker (`Closed`, `Open`, `Half-Open`) with persistent state, automatic rate-limit detection, and HTTP 429 `Retry-After` sleep overrides. |
| **Unified Cache** | `src/pipeline/unified_cache/`, `src/cache/` | Tiered caching (in-memory LRU + persistent SQLite/Redis) featuring request coalescing, stale-while-revalidate, and stage result deduplication. |
| **Frontier State & CRDTs** | `src/frontier/`, `src/core/frontier/state.py` | Conflict-Free Replicated Data Types (LWW-Sets) indexed by Hybrid Logical Clocks (HLCs) for eventually consistent discovery knowledge. |
| **Deterministic Replay Engine** | `src/core/frontier/replay_engine.py` | Pure sequential log replay from arbitrary WAL offsets for deterministic state reconstruction and post-replay invariant checks. |
| **ML Policy Governance & Raft Durability** | `src/learning/policy_governance.py`, `src/core/frontier/raft_fsm.py` | `PolicyGovernanceGate` with shadow evaluation against runaway positive feedback, canary promotion, atomic rollback to `parent_policy_id`, and `PromotePolicyCommand`/`RollbackPolicyCommand` committed into `PartitionFSM`. |
| **Prioritized QoS Telemetry Broker** | `src/realtime/prioritized_broker.py` | 5-lane QoS backpressure router (P0 Bounded Control with Secondary Spooling, P1 Lifecycle, P2 Coalesced Findings, P3 Telemetry Aggregates, P4 Debug Shedding). |
| **Execution Request Worker** | `src/execution/request_executor.py` | Stateless worker executing authorized tickets and emitting untrusted `RawExecutionClaim` envelopes with evidence hashes. |
| **Scope & Policy Authorization** | `src/decision/authorization.py` | Cryptographic `ScopeToken` validation, canonical identity binding, and mandatory committed budget reservation precondition (`INVARIANT-002`) issuing signed `AuthorizedExecutionTicket` leases. |
| **Reporting & Compliance** | `src/reporting/` | Multi-format vulnerability report generator (SARIF 2.1.0, JSON, Markdown, CSV, cryptographically signed PDF) and compliance mappings (SOC 2, ISO 27001, PCI-DSS). |

---

## Core System Invariants

1. **One Authoritative State Machine & Transactional Settlement**:
   - Execution workers produce untrusted `RawExecutionClaim` envelopes and cannot mutate state directly.
   - `SettlementCoordinator` executes 5-stage verification (signatures, epoch fencing, canonical scope, proof hashes, quota) before committing settlement records to the Write-Ahead Log (WAL), which subsequently drives independent projections.
2. **Partitioned Single-Writer & Epoch Fencing**:
   - Target identities are consistently hashed to partition leaders.
   - Every lease carries an incrementing `epoch`. Stale claims (`claim.epoch < current_epoch`) are rejected with zero side effects.
3. **Deterministic Canonical Identity**:
   - Scope authorization and tickets bind directly to normalized `CanonicalTargetIdentity` with pinned DNS snapshots.
4. **Out-of-Band ML Policy Governance**:
   - Machine learning algorithms optimize priority without authority to bypass security rules. Candidate policies are shadow-evaluated and canary-promoted.
5. **Prioritized QoS Telemetry**:
   - Critical control events (P0) are strictly preserved while lower-priority debug logs (P4) are shed during backpressure saturation.

---

## Further Reading

- [System Architecture Deep Dive](architecture.md) — The 10 Laws of Distributed Correctness, formal invariants, and state machine lifecycles.
- [Codebase Map](codebase.md) — Full package and file catalog.
- [Failure Modes & Diagnostics](FAILURE_MODES.md) — Interpreting scan degradation and triage flows.
- [Commands Reference](commands.md) — CLI and runtime command options.
- [Environment Variables](environment-variables.md) — Full configuration catalog.
