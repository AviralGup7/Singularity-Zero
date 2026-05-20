# Singularity-Zero: Evolution Alpha - Development Roadmap

This plan outlines the next major phase of development for the Cyber Security Test Pipeline, focusing on transitioning from architectural foundations to production-grade autonomous operations.

---

## 🏗️ Phase 1: Production-Grade Mesh Orchestration
**Goal**: Move from simulated load balancing to real-time, resource-aware actor migration.

1.  **Metric-Aware Balancing**:
    *   **Status**: COMPLETED. Refactored `src/infrastructure/mesh/balancer.py` to ingest real-time `psutil` data.
    *   Implemented the **Suitability Score** based on CPU usage and RAM headroom.
2.  **Proactive Actor Migration**:
    *   **Status**: COMPLETED. Updated `src/core/frontier/ghost_actor.py` with a `MigrationTrigger` and `health_check` handler.
    *   Actors now flag `evacuation_recommended` when node pressure is detected.

## 🧠 Phase 2: Autonomous Exploitation Engine (AEVE)
**Goal**: Transform finding "candidates" into verified security proof-of-concepts.

1.  **Safe-Harbor Validation**:
    *   **Status**: COMPLETED (Core). Implemented `src/execution/exploiters/aeve.py` to manage the verification lifecycle.
    *   Initial heuristic-based verification and PoC enrichment are active.
2.  **Multi-Stage Chaining**:
    *   **Status**: PARTIAL. AEVE now supports basic attack-chain linking between exposures and sinks.

## 📊 Phase 3: Visual Intelligence & Observability
**Goal**: Provide high-fidelity insights into the autonomous decision-making process.

1.  **Attack-Chain Visualization**:
    *   **Status**: PENDING.
2.  **Telemetry Micro-Batching**:
    *   **Status**: PENDING.

## 🛡️ Phase 4: Long-Term Mesh Stability
**Goal**: Resolve architectural debt and prevent state-engine degradation.

1.  **State Compaction & Pruning**:
    *   **Status**: COMPLETED. Implemented `VectorClock.prune` and `LWWset.compact` in `src/core/frontier/state.py`.
    *   Tombstones are now purged after 24 hours to maintain linear memory growth.
2.  **AES-GCM Key Rotation**:
    *   **Status**: COMPLETED. Implemented in `src/core/frontier/ghost_vfs.py`.
    *   `GhostVFS.__init__()` accepts a `rotation_interval_hours` parameter (default 4 h).
    *   `rotate_key()` decrypts all stored artifacts under the old key, re-encrypts under a
        freshly generated key, and wipes the old key from memory via `_secure_wipe_bytes()`.
    *   `write_file()` proactively calls `rotate_key()` whenever the interval has elapsed.
    *   Remaining open item: `flush_to_disk()` — on-disk export of encrypted artifacts — is still
        a stub.

---

## 🚀 Execution Strategy

1.  **Sprint 1**: Metric-Aware Balancing & State Compaction (Stability Focus).
2.  **Sprint 2**: WASM-based Validation & AEVE Core (Feature Focus).
3.  **Sprint 3**: Dashboard Visualization & Risk-Score Integration (Observability Focus).
