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
| **Frontier State & CRDTs** | `src/frontier/`, `src/core/frontier/` | Conflict-Free Replicated Data Types (LWW-Sets) indexed by Hybrid Logical Clocks (HLCs) providing causal state ordering with $O(1)$ node space complexity, backed by an append-only WAL. |
| **Distributed Actor Mesh** | `src/mesh/`, `src/infrastructure/mesh/` | Peer-to-peer clustering via authenticated SWIM gossip, dynamic node capability tracking, and consistent-hashing shard balancing. |
| **Real-Time Telemetry & WebSockets** | `src/websocket_server/`, `src/realtime/` | High-throughput WebSocket server with MessagePack/JSON serialization, heartbeats, channel-based event multiplexing, and backpressure shedding. |
| **Dashboard & API Layer** | `src/dashboard/fastapi/`, `src/console/` | FastAPI REST services exposing OpenAPI 3.1 contracts, JWT RBAC security, audit logging, live stage metrics, and operator console handlers. |
| **Closed-Loop Active Learning** | `src/learning/`, `src/intelligence/`, `src/intel/` | Adaptive ML severity classifier (XGBoost/Scikit-Learn with pure NumPy fallback), automated false-positive suppression, and Nuclei tag prioritization retrained from analyst triage signals. |
| **Decision & Attack Planning** | `src/decision/` | Adaptive attack selection, priority queues, and hunt budgets. Emits formal `ExecutionRequest` contracts of intent. |
| **Execution Request Worker** | `src/execution/request_executor.py` | Stateless execution of authorized requests with strict resource budgets and sandbox supervision, emitting `ExecutionResult`. |
| **Scope & Policy Authorization** | `src/decision/authorization.py` | Cryptographic `ScopeToken` validation (domain wildcards, CIDRs, forbidden paths) issuing signed `AuthorizedExecutionTicket` leases. |
| **Reporting & Compliance** | `src/reporting/` | Multi-format vulnerability report generator (SARIF 2.1.0, JSON, Markdown, CSV, cryptographically signed PDF) and compliance mappings (SOC 2, ISO 27001, PCI-DSS). |

---

## Core System Invariants

1. **Immutable Stage Contracts & State Authority**:
   - Pipeline stages accept immutable `StageInput` / `ExecutionRequest` contracts and must return `StageOutput` / `ExecutionResult` containing state deltas.
   - Workers are strictly forbidden from directly writing to CRDTs or storage; all state mutations are validated and committed exclusively by the `State Authority` via the Write-Ahead Log (WAL).
2. **Centralized Authorization Gate**:
   - The Speculative Dispatcher mints requests carrying authorization context, which must pass the independent `Authorization & Resource Gate` (`src/decision/authorization.py`) before worker placement.
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
