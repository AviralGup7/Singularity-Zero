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
                                             ▼                     │ ├── Distributed WAL / Storage  │
                         ┌───────────────────────────────────────┐ │ └── Actor Mesh (src/mesh/)    │
                         │   Enrichment & Reporting Sinks        │ └───────────────────────────────┘
                         │   ├── ML Severity & Learning Engine   │
                         │   │   (src/learning/, src/intel/)     │
                         │   └── Report Attestation (src/reporting/) │
                         └───────────────────────────────────────┘
```

---

## Subsystems & Implementation Map

| Subsystem | Location | Technical Implementation & Responsibilities |
|---|---|---|
| **Reconnaissance Engine** | `src/recon/` | Multi-source asynchronous OSINT collectors (Wayback, CommonCrawl, AlienVault, OTX, Shodan), DNS wildcard elimination, JS AST route extraction, and cloud asset mapping (AWS S3, Azure Blob, GCP). |
| **Active & Passive Analysis** | `src/analysis/` | Heuristic vulnerability detectors (SQLi, XSS, IDOR/BAC, JWT forgery, HTTP/2 smuggling, CSP bypass) emitting structured `AnalyzerResult` events. |
| **Exploitation & Sandboxing** | `src/exploitation/`, `src/sandbox/`, `src/execution/` | End-to-end exploit validation harnesses. PoCs run isolated within a `wasmtime` WebAssembly runtime or isolated sandboxed subprocesses with strict resource quotas. |
| **Detection Catalog & Rules** | `src/detection/` | Centralized vulnerability signature registry, coverage mapping, mode matrix configuration (Safe, Aggressive, Stealth), and AST rule engines. |
| **Pipeline DAG Orchestrator** | `src/pipeline/`, `src/pipeline/services/pipeline_orchestrator/` | Asynchronous DAG executor (`GraphBuilder`, `ActorScheduler`, `Orchestrator`) handling task dependency resolution, speculative dispatch, checkpoint persistence, and resume flows. |
| **Resilience & Circuit Breaking** | `src/resilience/` | 3-state Circuit Breaker (`Closed`, `Open`, `Half-Open`) with persistent state, automatic rate-limit detection, and HTTP 429 `Retry-After` sleep overrides. |
| **Unified Cache** | `src/pipeline/unified_cache/`, `src/cache/` | Tiered caching (in-memory LRU + persistent SQLite/Redis) featuring request coalescing, stale-while-revalidate, and stage result deduplication. |
| **State Authority & Settlement** | `src/core/frontier/state_authority.py` | Centralized `StateAuthority` (WAL logging, schema validation, CRDT state merge, execution deduplication) and `SettlementCoordinator` (Transactional WAL Settlement Intent + Idempotent Projections for CRDT, Budget, and Queue). |
| **Frontier State & CRDTs** | `src/frontier/`, `src/core/frontier/` | Conflict-Free Replicated Data Types (LWW-Sets) indexed by Hybrid Logical Clocks (HLCs with $O(1)$ clock comparison overhead, $O(N)$ element space), backed by an append-only WAL. |
| **Distributed Actor Mesh** | `src/mesh/`, `src/infrastructure/mesh/` | Peer-to-peer clustering via authenticated SWIM gossip, dynamic node capability tracking, and consistent-hashing shard balancing. |
| **Real-Time Telemetry & WebSockets** | `src/websocket_server/`, `src/realtime/` | High-throughput WebSocket server with MessagePack/JSON serialization, heartbeats, channel-based event multiplexing, and non-lossy critical event backpressure protection. |
| **Dashboard & API Layer** | `src/dashboard/fastapi/`, `src/console/` | FastAPI REST services exposing OpenAPI 3.1 contracts, JWT RBAC security, audit logging, live stage metrics, and operator console handlers. |
| **Statistical Calibration & Adaptive Learning** | `src/learning/`, `src/intelligence/` | Closed-loop PI-controller threshold tuner, calibrated logistic severity scoring, Bayesian Beta-Binomial Nuclei tag optimizer, and immutable `VersionedPolicy` generation for the priority engine. |
| **Decision & Attack Planning** | `src/decision/` | Adaptive attack selection, priority queues (`CorrelationPriorityQueue`), and hunt budgets. Emits formal `ExecutionRequest` contracts of intent with candidate leases. |
| **Execution Request Worker** | `src/execution/request_executor.py` | Stateless execution of authorized requests with mandatory `AuthorizedExecutionTicket` verification and sandbox supervision, emitting `ExecutionResult`. |
| **Scope & Policy Authorization** | `src/decision/authorization.py` | Cryptographic `ScopeToken` validation (domain wildcards, CIDRs, forbidden paths) and atomic budget reservation issuing signed `AuthorizedExecutionTicket` leases. |
| **Reporting & Compliance** | `src/reporting/` | Multi-format vulnerability report generator (SARIF 2.1.0, JSON, Markdown, CSV, cryptographically signed PDF) and compliance mappings (SOC 2, ISO 27001, PCI-DSS). |

---

## Core System Invariants

1. **Immutable Stage Contracts & Authoritative WAL Settlement**:
   - Pipeline stages accept immutable `StageInput` / `ExecutionRequest` contracts and return `StageOutput` / `ExecutionResult`.
   - Workers are strictly forbidden from directly writing to CRDTs or storage; all state mutations, budget allocations, and lease acknowledgements are committed atomically to the Write-Ahead Log (WAL) as a `SettlementIntent` via `SettlementCoordinator` ➔ `StateAuthority`, driving idempotent downstream projections.
2. **Centralized Authorization Gate & Mandatory Tickets**:
   - The Speculative Dispatcher mints requests carrying authorization context, which must pass the independent `Authorization & Resource Gate` (`src/decision/authorization.py`) to atomically reserve budget and receive an `AuthorizedExecutionTicket`.
   - `ExecutionRequestWorker.execute(ticket)` strictly rejects unauthenticated raw `ExecutionRequest` instances.

3. **Sensitive Credential Scrubbing**:
   - Hostname and target validation: `src/recon/domain_validation.py` and `src/core/utils/url_validation.py`.
   - Sensitive credential scrubbing and header masking: `src/core/security/sensitive_names.py`.
4. **Resilience & Graceful Degradation**:
   - Subprocess and tool executions are gated by `src/pipeline/services/circuit_breaker.py` with HTTP 429 `Retry-After` enforcement (`src/resilience/retry_after.py`).
5. **Execution Sandboxing**:
   - Dynamic plugin and exploit verification runs inside process/WASM sandboxes with AST validation (`src/core/plugins/sandbox.py`).

---

## Further Reading

- [System Architecture Deep Dive](architecture.md) — Detailed data flow, actor lifecycles, and state replication.
- [Codebase Map](codebase.md) — Full package and file catalog.
- [Failure Modes & Diagnostics](FAILURE_MODES.md) — Interpreting scan degradation and triage flows.
- [Commands Reference](commands.md) — CLI and runtime command options.
- [Environment Variables](environment-variables.md) — Full configuration catalog.
