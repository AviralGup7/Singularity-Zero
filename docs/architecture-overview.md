# Architecture Overview

This document provides a **non-marketing, engineering-focused** map of the Cyber Security Test Pipeline. It details the structural design patterns, data flow mechanisms, and modules that implement them across the codebase.

**Dual log:** live `cstp scan` / `src.pipeline.runtime` settles on **FrontierWAL** (F-004). Raft **PartitionWAL** is the authority plane (F-003), single-node quorum-1. `attach_pipeline_authority` is fail-closed (exit 3). Do not unify the logs or invent a multi-host cluster.

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
| **Coverage-Guided & Protocol Fuzzing** | `src/fuzzing/` | Production-grade coverage-guided mutation engine (`CorpusManager`, `CoverageTracker`), native process `ForkServer` crash containment, and protocol fuzzers (HTTP/2 frames, QUIC, gRPC, GraphQL batch, AST grammar). |
| **Bayesian Decision & Adaptive Flow Control** | `src/decision/`, `src/infrastructure/flow_control/` | Multi-Armed Bayesian Bandit (`BayesianParameterBandit`) balancing exploration vs. exploitation via Thompson Sampling & UCB1, coupled with closed-loop `AdaptivePIDController` rate pacing and Bulkhead connection isolation. |
| **Multi-Cloud Recon & Threat Intelligence** | `src/recon/cloud_recon/`, `src/intelligence/` | Multi-cloud storage and service enumerators (AWS, Azure, GCP, Firebase, Wasabi, OCI, DigitalOcean, Backblaze) and real-time `ThreatIntelEnricher` (CISA KEV, FIRST EPSS, CVSS v4, MISP, Shodan, OTX, VirusTotal). |
| **WAF Evasion & AST Taint Analysis** | `src/detection/` | Hidden Markov Model WAF evader (`hmm_evader.py`), JS AST sink taint analyzer (`js_sink_analyzer.py`), prototype pollution walker, WASM introspector, and dynamic headless browser DOM-XSS validation. |
| **P2P Mesh, Ghost Actors & Task Auction** | `src/infrastructure/mesh/`, `src/infrastructure/frontier/` | SWIM Gossip protocol engine, node failure detection, Ghost Actor VFS, Bloom mesh target synchronization, and distributed task auction bidding (`bidder.py`, `balancer.py`). |
| **Reporting, Bounty Sinks & Compliance** | `src/reporting/` | Exporters for 12+ bug bounty platforms (HackerOne, Bugcrowd, Intigriti, Synack, YesWeHack, Google VRP, etc.) and evidence-backed compliance mapping for SOC 2, ISO 27001, PCI-DSS v4.0, and NIST 800-53. |
| **Job Lifecycle, Watchdog & Notifications** | `src/jobs/`, `src/notifications/` | Job state machine transitions, deadlock/hang detection (`Watchdog`), scan dry-run simulation, and central event-driven notification bridge with snooze, digest aggregation, and escalation policies. |
| **Partitioned Raft FSM & Replicated Log** | `src/core/frontier/raft_fsm.py`, `src/core/frontier/replicated_log.py` | Partitioned in-memory Raft FSM engine ($L_0$ Replicated Log $\rightarrow$ $L_1$ Deterministic Pure FSM) with multi-replica identical application, zero external I/O, deterministic `CommandResult`, emitted event envelopes, and leader-signed certified receipts (`CommandReceipt`). |
| **Global Coordination (`P-0000`) & Run Sagas** | `src/core/frontier/global_coordination.py`, `src/core/frontier/run_saga.py` | `GlobalBudgetAggregate` (exact integer conservation: $\text{Total} = \text{Consumed} + \text{Outstanding} + \text{Available}$, linearized lease termination, `expire_sublease` timeout reclaim), `PlacementAuthority` (5-stage fenced migration), and `DurableRunSagaEngine`. |
| **Authoritative State & Settlement** | `src/core/frontier/state_authority.py`, `src/pipeline/authority_bootstrap.py` | **Dual log:** live scan settles `SettlementIntent` on **FrontierWAL** via `settle_stage_output` (FAILED attempt status `REJECTED`). Raft `PartitionWAL` + 5-stage `settle_claim` is the authority plane (CLI quorum-1). Attach is fail-closed exit 3; `apply_authority_recovery` runs after attach. Checkpoints are L3 caches (`verify_checkpoint_against_fsm` warns). |
| **Command Envelopes & Event Upcasting** | `src/core/contracts/command_envelope.py` | Strongly-typed `CommandEnvelope`, Model B `CommittedEntry` carrying deterministic event envelopes ($\text{event\_id} = \text{SHA256}(\text{partition} \mathbin{\Vert} \text{index} \mathbin{\Vert} \text{seq})$), and `SchemaUpcasterRegistry`. |
| **Canonical Target & State Encoding** | `src/core/contracts/canonical_target.py` | Deterministic target identity separation (`CanonicalHostIdentity`, `CanonicalNetworkEndpoint`, `CanonicalUrl`, `AuthorizationTarget`), IDNA normalization, port preservation/elision, and DNS snapshot pinning. |
| **Projection Vector Watermarks & Cold Rebuild** | `src/core/frontier/projection_stream.py` | Level 3 materialized read models with `ProjectionCheckpointVector` tracking `(partition, term, index, hash)`, gap detection ($K > \text{last} + 1 \Rightarrow \text{GAP\_DETECTED}$), and parallel cold rebuild from offset 0. |
| **Formal Invariants Verification** | `src/core/frontier/invariant_checker.py`, `causal_identity.py`, `failure_model.py`, `recovery_protocol.py`, `region_model.py` | I1–I29 in `tests/unit/test_formal_invariants.py`. I30–I32 in `test_global_invariants.py`. I33 `test_causal_identity.py`. I34 `test_failure_model.py`. I35 `test_recovery_protocol.py`. I36 `test_region_model.py`. I37 `test_authority_transfer.py`. |
| **Reconnaissance Engine** | `src/recon/` | Multi-source asynchronous OSINT collectors (Wayback, CommonCrawl, AlienVault, OTX, Shodan), DNS wildcard elimination, JS AST route extraction, and cloud asset mapping. |
| **Active & Passive Analysis** | `src/analysis/` | Heuristic vulnerability detectors (SQLi, XSS, IDOR/BAC, JWT forgery, HTTP/2 smuggling, CSP bypass) emitting structured `AnalyzerResult` events. |
| **Exploitation & Sandboxing** | `src/exploitation/`, `src/sandbox/`, `src/execution/` | End-to-end exploit validation harnesses. PoCs execute inside OS-level process cages (`ProcessSandbox`) with credential stripping and POSIX limits; WASM runtime is feature-flagged. |
| **Pipeline DAG Orchestrator** | `src/pipeline/`, `src/pipeline/services/pipeline_orchestrator/` | Asynchronous DAG executor (`GraphBuilder`, `ActorScheduler`, `Orchestrator`) handling task dependency resolution, speculative dispatch, checkpoint persistence, and resume flows. |
| **Resilience & Circuit Breaking** | `src/resilience/` | 3-state Circuit Breaker (`Closed`, `Open`, `Half-Open`) with persistent state, automatic rate-limit detection, and HTTP 429 `Retry-After` sleep overrides. |
| **Unified Cache** | `src/pipeline/unified_cache/`, `src/cache/` | Tiered caching (in-memory LRU + persistent SQLite/Redis) featuring request coalescing, stale-while-revalidate, and stage result deduplication. |
| **Frontier State & CRDTs** | `src/frontier/`, `src/core/frontier/state.py` | Conflict-Free Replicated Data Types (LWW-Sets) indexed by Hybrid Logical Clocks (HLCs) for eventually consistent discovery knowledge. |
| **Deterministic Replay Engine** | `src/core/frontier/replay_engine.py` | Pure sequential log replay from arbitrary WAL offsets for deterministic state reconstruction and post-replay invariant checks. |
| **ML Policy Governance & Raft Durability** | `src/learning/policy_governance.py`, `src/core/frontier/raft_fsm.py` | `PolicyGovernanceGate` with pre-promotion schema validation, safety bounds $[0.0, 1.0]$, shadow evaluation against runaway positive feedback, canary promotion, and version-fenced atomic rollback to `parent_policy_id`. |
| **Prioritized QoS Telemetry Broker** | `src/realtime/prioritized_broker.py` | 5-lane QoS backpressure router (P0 Bounded Control with Framed Crash-Durable Local Spooling, P1 Lifecycle, P2 Coalesced Findings, P3 Telemetry Aggregates, P4 Debug Shedding). |
| **Execution Request Worker** | `src/execution/request_executor.py` | Stateless worker executing authorized tickets and emitting untrusted `RawExecutionClaim` envelopes with evidence hashes. |
| **Scope & Policy Authorization** | `src/decision/authorization.py` | Cryptographic `ScopeToken` validation, canonical identity binding, and fail-closed mandatory committed budget reservation precondition (`INVARIANT-002`) issuing signed `AuthorizedExecutionTicket` leases. |
| **Reporting & Compliance** | `src/reporting/` | Multi-format vulnerability report generator (SARIF 2.1.0, JSON, Markdown, CSV, cryptographically signed PDF) and compliance mappings (SOC 2, ISO 27001, PCI-DSS). |

---

## Single Source of Authority Specification

| Decision / State Domain | Single Authoritative Component | Non-Authoritative / Proposal Layer |
|---|---|---|
| **Authoritative State Mutation** | `PartitionFSM.apply(CommittedEntry)` | Execution Workers (`RawExecutionClaim`), Outbox Stream |
| **Global Quota & Sub-leases** | `GlobalBudgetAggregate` ($P\text{-}0000$) | Local Enforcers, `SettlementCoordinator` |
| **Partition Ownership & Migration** | `PlacementAuthority` ($P\text{-}0000$) | Actor Mesh, Local Schedulers |
| **Execution Authorization** | `ExecutionAuthorizer` + Scope Tokens | Speculative Dispatcher |
| **Lease & Ticket Settlement** | `PartitionFSM` (`SubmitExecutionClaim`) | `SettlementCoordinator` (Validation/Proposer) |
| **Policy Durability & Promotion** | `PartitionFSM` (`PromotePolicyCommand`) | `PolicyGovernanceGate` (Shadow Evaluation/Canary) |
| **Node Failure & Peer Discovery** | SWIM Gossip Protocol (`src/infrastructure/mesh/`) | None (Observation & Health telemetry only) |
| **Task Candidate Recommendation**| Task Auction & Bidder (`src/infrastructure/frontier/`) | None (Scheduling proposal only) |
| **Materialized Views / Query** | `ProjectionCheckpointVector` Consumers | Projections are derived from WAL, never write |
| **Local Performance & Sync Aid** | Tiered Cache & Ghost VFS | Ephemeral / reconstructible from WAL snapshots |

---

## Core System Invariants

1. **One Authoritative State Machine & Transactional Settlement**:
   - Execution workers produce untrusted `RawExecutionClaim` envelopes and cannot mutate state directly.
   - `SettlementCoordinator` executes 5-stage verification (signatures, epoch fencing, canonical scope, proof hashes, quota) and proposes committed claims into the Raft log/FSM, which subsequently drives independent projections.
2. **Partitioned Single-Writer & Epoch Fencing**:
   - Target identities are consistently hashed to partition leaders.
   - Every lease carries an incrementing `epoch`. Stale claims (`claim.epoch < current_epoch`) are rejected with zero side effects.
3. **Deterministic Canonical Identity**:
   - Scope authorization and tickets bind directly to normalized `CanonicalTargetIdentity` with pinned DNS snapshots.
4. **Out-of-Band ML Policy Governance**:
   - Machine learning algorithms optimize priority without authority to bypass security rules. Candidate policies are shadow-evaluated, bounded, and canary-promoted.
5. **Prioritized QoS Telemetry & Crash-Durable Spooling**:
   - Critical control events (P0) are spooled locally with framed CRC records, while lower-priority debug logs (P4) are shed during backpressure saturation.

---

## Further Reading

- [System Architecture Deep Dive](architecture.md) — The 10 Laws of Distributed Correctness, formal invariants, and state machine lifecycles.
- [Codebase Map](codebase.md) — Full package and file catalog.
- [Failure Modes & Diagnostics](FAILURE_MODES.md) — Interpreting scan degradation and triage flows.
- [Commands Reference](commands.md) — CLI and runtime command options.
- [Environment Variables](environment-variables.md) — Full configuration catalog.
