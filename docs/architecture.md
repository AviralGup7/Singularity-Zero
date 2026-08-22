# Project Architecture: Cyber Security Test Pipeline

## Implementation Status & Engineering Ground Truth

This document outlines the architecture, distributed execution model, resilience mechanisms, and cognitive analysis components of the Cyber Security Test Pipeline. The table below delineates production-shipped components from research and prototype systems:

| Subsystem / Capability | Current Status | Code Location |
|---|---|---|
| **DAG Pipeline Orchestrator** | **Production** — Async DAG builder, actor scheduler, stage lifecycle, speculative dispatch | `src/pipeline/services/pipeline_orchestrator/`, `src/pipeline/engine.py` |
| **Resilience & Circuit Breaking** | **Production** — 3-state Circuit Breaker, Redis/SQLite persistence, HTTP 429 `Retry-After` sleep override | `src/resilience/` |
| **Unified Hierarchical Cache** | **Production** — In-memory LRU + SQLite/Redis tiered cache with single-flight request coalescing | `src/pipeline/unified_cache/`, `src/cache/` |
| **Frontier State & CRDT Engine** | **Production** — LWW-Set CRDTs keyed by Hybrid Logical Clocks (HLC), journaled state deltas | `src/frontier/`, `src/core/frontier/` |
| **Tamper-Evident Audit Ledger** | **Production** — Cryptographic HMAC-SHA256 chained audit trail for administrative and scan events | `src/auth/audit.py`, `src/console/audit.py` |
| **Active & Passive Analyzers** | **Production** — Multi-stage detectors for SQLi, XSS, SSRF, JWT, CSP, HTTP/2 smuggling | `src/analysis/active/`, `src/analysis/passive/` |
| **ML Severity & Active Learning** | **Production** — XGBoost / Scikit-Learn classifier with NumPy fallback, automated FP feedback loop | `src/learning/`, `src/intel/` |
| **Adaptive Nuclei Tag Optimizer** | **Production** — Per-tag precision/recall/F1 telemetry tracking with dynamic config overrides | `src/learning/nuclei_tag_optimizer.py` |
| **WASM / Process Sandbox** | **Production** — `wasmtime` runtime isolation for PoC verification; AST validation child process loader | `src/sandbox/`, `src/execution/` |
| **3D Cockpit & Real-time Console** | **Production** — React 19 + Three.js instanced attack graph rendering, Zustand stores, WebSockets | `frontend/src/`, `src/websocket_server/` |
| **Distributed Actor Mesh** | **Production (Single-node & P2P)** — Pykka/Asyncio workers with SWIM gossip discovery and shard balancing | `src/mesh/`, `src/infrastructure/mesh/` |
| **Attack Graph & Path Prediction** | **Production / Heuristic** — Kuzu graph integration and 2-layer GCN path prediction fallback | `src/intelligence/graph/`, `src/analysis/intelligence/` |

---

## 🏛️ Core Principles & Execution Planes

### 1. The Distributed Execution Plane
- **Actor-Based Stage Scheduling**: Tasks are scheduled as asynchronous stage actors managed by `ActorScheduler` (`src/pipeline/services/pipeline_orchestrator/actor_scheduler.py`). The scheduler continuously evaluates dependency readiness futures and greedily dispatches runnable stages into worker pools without waiting for static tier synchronization bubbles.
- **CRDT Hybrid Logical Clock (HLC) Engine**: Frontier assets (subdomains, live hosts, endpoints, parameters, findings) are stored in Conflict-Free Replicated Data Types (`LWW-Sets`) indexed by Hybrid Logical Clocks. HLCs provide causal state consistency in $O(1)$ space per node, avoiding the unbounded network and memory overhead of classic vector clocks.
- **Durable Write-Ahead Logging (WAL)**: All state transitions emit immutable deltas recorded in a journal ledger (`src/frontier/journal.py`). When cluster checkpoints are enabled, snapshots are dual-committed to Redis Streams and local Append-Only Files (AOF), ensuring instantaneous recovery and resume from interrupted runs (`--resume-from <checkpoint_id>`).
- **Resilience & Circuit Breaker Isolation**: Network-bound tools and stages are wrapped by a 3-state Circuit Breaker (`src/resilience/circuit_breaker.py`). If a remote host or service throttles (HTTP 429) or times out, the breaker trips to `OPEN`, immediately parsing `Retry-After` delay headers (`src/resilience/retry_after.py`) to pause downstream dispatch without freezing event loops.

### 2. Cognitive Vulnerability Analysis & Validation
- **Differential State Probing**: `src/analysis/intelligence/differential_prober.py` compares responses across differing authentication roles and tenant boundaries using normalized Levenshtein distance, automatically discovering Insecure Direct Object References (IDOR) and Broken Access Controls (BAC).
- **PoC Validation Sandbox**: Exploit validation scripts and untrusted probes execute within a restricted WebAssembly sandbox (`wasmtime`) or isolated child processes with AST-enforced import restrictions (`src/sandbox/`), preventing unauthorized host breakout.
- **Adaptive Closed-Loop Learning**: The ML severity engine (`src/learning/`) extracts operator triage feedback in real time. False positives flagged by security analysts update the FP-rules repository (`src/learning/fp_rules.py`) and retrain severity calibration weights, suppressing duplicate noise across subsequent scan executions.

### 3. High-Throughput Hardware Acceleration
- **SIMD-Vectorized Processing**: URL parsing, domain filtering, and parameter mutation employ vectorized NumPy routines, filtering millions of candidate URLs in sub-second intervals.
- **Probabilistic Bloom Filtering**: MurmurHash3-backed Bloom filters accelerate cluster-wide URL and asset membership tests, preventing redundant scanning and saving gigabytes of working RAM.
- **Binary Wire Protocol**: High-throughput telemetry and mesh event streams utilize MessagePack (`msgpack`) zero-copy binary serialization alongside standard JSON payloads.

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
- **Supply-Chain Integrity**: Nuclei templates and scanning rules are validated at startup against Ed25519 cryptographic signatures and SHA-256 baseline manifests.
- **Contract Enforcement**: FastAPI endpoints strictly enforce Pydantic v2 validation models on the backend and Zod schema contracts on the frontend.
