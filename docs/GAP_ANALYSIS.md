# Gap Analysis: Cyber Security Test Pipeline

This document provides a realistic, technical audit of gaps between target specifications and current implementation in `src/`.

---

## 🏛️ 1. Distributed Core & Consensus

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **Distributed Raft Consensus & Transport** | Low | Implemented | `src/core/frontier/raft_transport.py` implements `RaftTransportProtocol`, `AppendEntriesRequest`/`Response`, `RequestVoteRequest`/`Response`, and `InMemoryRaftTransport`. `ReplicatedPartitionLog` enforces majority quorum ($N // 2 + 1$), term step-down, election failover, crash-safe disk WAL (`PartitionWAL` with CRC-64 + fsync), and durable outbox stream (`DurableOutboxLedger`). |
| **Multi-Node Actor Migration** | High | Single-Node | `GhostActorCoordinator` and `actor_scheduler.py` run in-process using Pykka and Asyncio (`src/infrastructure/frontier/ghost_actor.py`). Live actor migration across physical network hosts is not wired. |
| **Ghost-VFS RAM Isolation** | Medium | In-Memory Heap | Encrypted RAM isolation operates via Python `bytearray` and zeroing routines (`src/core/frontier/vfs_isolation.py`) rather than OS kernel-locked encrypted pages. |

---

## 🔒 2. Sandboxing & Isolation

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **WASM Runtime Sandboxing (AEVE)** | Medium | Feature Flagged | `src/execution/frontier/wasm.py` includes a `wasmtime` runner guarded behind `FEATURE_WASM_PLUGINS=false`, falling back to `_MockWasmtime`. Core scans use `ProcessSandbox`. |
| **MicroVM / Namespace Isolation** | Medium | Process-Only | Exploit and tool execution utilizes `ProcessSandbox` (`src/sandbox/process_sandbox.py`) enforcing POSIX `setrlimit` and env stripping. Kernel namespaces, cgroups, or MicroVMs are not implemented. |

---

## 🧠 3. Machine Learning & Evasion

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **Deep Reinforcement Learning (DRL) Policy** | Medium | Heuristic | `PPOEvasionModel` (`src/core/frontier/drl_evasion.py`) is implemented as a lightweight 2-layer matrix policy in pure Python. No external PyTorch or `stable-baselines3` dependency. |
| **GNN Graph Reasoning** | Medium | Dijkstra / Heuristic | Multi-hop lateral movement synthesis (`src/intelligence/graph/attack_graph.py`) uses Dijkstra's shortest path rather than trained Graph Neural Networks. |
| **Collaborative AI Swarm** | Low | Prototype | Swarm consensus modules in `src/intelligence/swarm/` remain experimental prototypes without live LLM backend wiring. |

---

## 🛡️ 4. Vulnerability & Analysis Engines

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **Advanced GraphQL Attack Scenarios** | Medium | Partial | Basic introspection, schema harvesting, and injection are implemented; alias-stacking and persisted-query hijacking are pending. |
| **Multi-Role Credential Matrix** | Medium | Open | Cross-role differential probing exists (`differential_prober.py`), but dynamic multi-role credential rotation across automated scan suites is open. |
| **Secrets Scanner Integration** | Low | In Progress | Passive secrets detection (`src/analysis/checks/passive/secrets_scanner.py`) exists and is being wired into default passive profiles. |

---

## 🔌 5. Integrations & Feeds

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **Enterprise Ticketing Sinks** | Low | Implemented | `JiraClient`, `ServiceNowClient`, and `DefectDojoClient` implemented in `src/reporting/platforms/` and registered into platform submission router and client factories. |
| **Threat Intelligence Feeds** | Medium | Partial | MISP client is implemented. VirusTotal and AlienVault OTX client wrappers exist for manual API queries, while live enrichment largely uses local CVE heuristics. |
| **AI Explainability Endpoints** | Low | Implemented | `GET /api/findings/{id}/ai-explain` and `GET /api/reports/ai-summary` fully implemented via `src/analysis/intelligence/finding_explainer.py` for Developer, Auditor, and Executive personas and scan risk index scoring. |
