# Gap Analysis: Cyber Security Test Pipeline

This document provides a realistic, technical audit of gaps between target specifications and current implementation in `src/`.

---

## 🏛️ 1. Distributed Core & Consensus

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **Distributed Raft Consensus & Transport** | Low | Implemented | `src/core/frontier/raft_transport.py` implements `RaftTransportProtocol`, `AppendEntriesRequest`/`Response`, `RequestVoteRequest`/`Response`, and `InMemoryRaftTransport`. `ReplicatedPartitionLog` enforces majority quorum ($N // 2 + 1$), term step-down, election failover, crash-safe disk WAL (`PartitionWAL` with CRC-64 + fsync), and durable outbox stream (`DurableOutboxLedger`). |
| **Multi-Node Actor Migration** | Medium | In-Process / Gossip Handoff | `GhostActorCoordinator` (`src/ghost_actors/ghost_actor_coordinator.py`) supports state serialization and handoff signalling across the gossip mesh (`src/ghost_actors/network_handoff.py`). Live process execution remains in-process. `initiate_transfer` (I37) is **tests-only** — no production scan-path caller. Live CLI is quorum-1; `NetworkRaftTransport` is LIBRARY. |
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
| **Secrets Scanner Integration** | Low | Implemented | Passive secrets detection (`src/analysis/checks/passive/secrets_scanner.py`) implements multi-pattern secret discovery (AWS, GitHub, Slack, DB strings, JWTs, private keys) with redacted matches and sha256 fingerprint deduplication. |

---

## 🔌 5. Integrations & Feeds

| Gap | Severity | Status | Technical Details & Current Code State |
|:---|:---|:---|:---|
| **Enterprise Ticketing Sinks** | Low | Implemented | `JiraClient`, `ServiceNowClient`, and `DefectDojoClient` implemented in `src/reporting/platforms/` and registered into platform submission router and client factories. |
| **Threat Intelligence Feeds** | Medium | Partial | MISP client is implemented. VirusTotal and AlienVault OTX client wrappers exist for manual API queries, while live enrichment largely uses local CVE heuristics. |
| **AI Explainability Endpoints** | Low | Implemented | `FindingExplainer` engine in `src/analysis/intelligence/finding_explainer.py` powers `GET /api/findings/{id}/ai-explain` (`routers/ai_explain.py`) and `GET /api/reports/ai-summary` (`routers/reports.py`) for Developer, Auditor, and Executive personas and scan risk index scoring. |

---

## ⚡ 6. State Settlement, Telemetry & Authority Ground Truth

| Capability | Production Reality & Implementation Architecture | Invariant Coverage |
|:---|:---|:---|
| **Settlement Architecture** | Production operates a durable, write-ahead reconciliation ledger (`SettlementCoordinator` writing `SettlementIntent` to `StateAuthority.wal` with projection engine listeners and `replay_from_wal()` rehydration). Raft WAL-backed projection settlement remains an optional future migration path. | `test_distributed_invariants.py` |
| **P0 Telemetry Durability** | Bounded in-memory queue (`p0_capacity=1000`) with durable append-only disk journal (`p0_telemetry_spool.jsonl` with `os.fsync`), startup rehydration, and explicit backpressure on total capacity saturation. | `test_hardened_authority_invariants.py` |
| **ML Policy Authority** | `PolicyGovernanceGate` evaluates candidates and commits active versioning via `PromotePolicyCommand`/`RollbackPolicyCommand` dispatched through the Raft log to `PartitionFSM`. | `test_hardened_authority_invariants.py` |
| **Global Budget Expiry** | Sublease timeout transitions on `P-0000` advance through `ExpireSubLeaseCommand` committed to the Raft FSM, maintaining integer conservation $\text{Total} \equiv \text{Consumed} + \text{Outstanding} + \text{SlabReserved} + \text{Available}$ (I5/I26). | `test_formal_invariants.py` |
| **Execution Authorization** | Unified `ExecutionAuthorizer.authorize` requiring `reserve_with_identity` (I30), ticket consume, and budget settlement across all execution entrypoints (both `stage_admit` pipeline stages and standalone `SafeExploiter` exploitation). | `test_global_invariants.py`, `test_formal_invariants.py` |
| **I29 Universal Egress Authority** | Universal network primitive interception in `egress_context.py` covering HTTP (`httpx`, `requests`), raw TCP/UDP (`socket.socket.connect`, `socket.create_connection`), async streams (`asyncio.open_connection`), headless browser (`runtime_browser.py`), and subprocesses with mandatory transport primitive registration. | `test_i29_egress_context.py`, `test_formal_invariants.py` |
| **I35 recovered tickets** | `collect_recovered_proof_artifacts` reads explicit `tickets`/`settlements`/`identities` keys plus WAL settlement intents. Checkpoint payloads typically have **none** of those keys → VERIFY_INVARIANTS often no-ops. `delivered_event_ids` empty by design. | `test_recovery_protocol.py`, `test_invariant_graph.py` |

