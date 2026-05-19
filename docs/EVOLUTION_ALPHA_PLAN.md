# Singularity-Zero: Evolution Alpha - Development Roadmap

This plan outlines the next major phase of development for the Cyber Security Test Pipeline, focusing on transitioning from architectural foundations to production-grade autonomous operations.

---

## 🏗️ Phase 1: Production-Grade Mesh Orchestration
**Goal**: Move from simulated load balancing to real-time, resource-aware actor migration.

1.  **Metric-Aware Balancing**:
    *   Refactor `src/infrastructure/mesh/balancer.py` to ingest real-time `psutil` data (CPU, RAM, Disk I/O, Network Latency) from peer nodes.
    *   Implement the **Suitability Score** based on current resource headroom instead of historical success alone.
2.  **Proactive Actor Migration**:
    *   Update `src/core/frontier/ghost_actor.py` with a `MigrationTrigger` that fires when a node's health score drops below a configurable threshold.
    *   Implement "Soft Failover": Actors serialize state to Redis and spin up on a colder node before the hot node reaches critical exhaustion.

## 🧠 Phase 2: Autonomous Exploitation Engine (AEVE)
**Goal**: Transform finding "candidates" into verified security proof-of-concepts.

1.  **Safe-Harbor Validation**:
    *   Expand `src/execution/exploiters/exploit_automation.py` to execute the generated Python/Curl PoCs within a hardware-isolated **WASM Sandbox** (`src/core/frontier/wasm.py`).
    *   Automatically tag findings as `VERIFIED_TP` if the validation yields a confirmed injection or state leak.
2.  **Multi-Stage Chaining**:
    *   Implement a logic layer that uses the `Kuzu` Attack-Chain database to "link" findings. For example: Use a `Token Leak` finding as the `Authorization` header for an `IDOR` validation attempt.

## 📊 Phase 3: Visual Intelligence & Observability
**Goal**: Provide high-fidelity insights into the autonomous decision-making process.

1.  **Attack-Chain Visualization**:
    *   Implement the `/risk-score` dashboard page with a real-time D3/Three.js graph showing multi-hop attack paths.
    *   Visually differentiate between "Candidate" nodes (potential bugs) and "Verified" nodes (confirmed by AEVE).
2.  **Telemetry Micro-Batching**:
    *   Implement the **Action Buffer Engine** in the frontend to handle massive throughput bursts (10k+ events/sec) without UI thread blocking.

## 🛡️ Phase 4: Long-Term Mesh Stability
**Goal**: Resolve architectural debt and prevent state-engine degradation.

1.  **State Compaction & Pruning**:
    *   Implement a background routine in `src/core/frontier/state.py` to prune Vector Clock entries for nodes that have been offline for >24 hours.
    *   Implement "Snapshot Compaction": Periodically collapse the CRDT history into a base snapshot to keep ` NeuralState` growth linear.
2.  **AES-GCM Key Rotation**:
    *   Harden `src/core/frontier/ghost_vfs.py` by implementing temporal key rotation for the RAM-only filesystem.

---

## 🚀 Execution Strategy

1.  **Sprint 1**: Metric-Aware Balancing & State Compaction (Stability Focus).
2.  **Sprint 2**: WASM-based Validation & AEVE Core (Feature Focus).
3.  **Sprint 3**: Dashboard Visualization & Risk-Score Integration (Observability Focus).
