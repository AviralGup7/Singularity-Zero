# Comprehensive Gap Analysis: Singularity-Zero

This document provides a high-level overview of the functional, architectural, and security gaps within the Cyber Security Test Pipeline. It serves as a roadmap for future development and hardening efforts.

---

## 🏗️ 1. Architectural Gaps

### 1.1 Actor-Mesh Maturity
- **Status**: Functional
- **Completed**: `Balancer` mesh balancer (`src/infrastructure/mesh/balancer.py`) ingests real-time `psutil`
  data to compute a multi-factor Suitability Score (CPU, RAM, reputation, efficiency). `GhostActor`
  (`src/core/frontier/ghost_actor.py`) exposes an `evacuation_recommended` flag on `ActorState`.
- **Gap**: Automated mid-execution actor *migration* — performing a live state transfer across the
  distributed mesh — is not yet implemented. The current code enables the *decision* to migrate but
  does not yet move the running actor to a colder node.
- **Impact**: Load-balancing decisions are accurate; workload is not yet redistributed mid-execution.
- **Mitigation**: Implement live actor serialization and re-hydration on the target worker node.

### 1.2 State Consistency (CRDT)
- **Status**: COMPLETED
- **Completed**: `VectorClock.prune(active_node_ids)` and `LWWset.compact()` are implemented in
  `src/core/frontier/state.py`. Tombstones are purged by age threshold. `NeuralState.compact()`
  handles the top-level aggregation. An e2e regression test exists at `tests/e2e/test_state_compaction.py`.
- **Remaining gap**: Long-running, multi-day jobs can still accumulate vector-clock entries for
  nodes that have left the mesh until the next explicit `prune()` call; a periodic background
  sweeper that calls `NeuralState.compact()` on a fixed interval has not been wired into the
  pipeline lifecycle hook yet.
- **Impact**: Low — compaction is triggered on every stage boundary and manual `prune()` calls are
  effective; no growth leak in normal scan durations.
- **Mitigation**: Add a periodic background compaction task callable from the pipeline lifecycle.

### 1.3 Anti-Forensic Persistence
- **Status**: Functional
- **Gap**: `GhostVFS` (`src/core/frontier/ghost_vfs.py`) implements temporal AES-GCM key rotation.
  The constructor accepts `rotation_interval_hours` (default 4.0 h); `rotate_key()` decrypts every
  stored file with the old key, re-encrypts everything under a fresh key, and attempts a secure
  memory wipe of the old key material. Rotation is also triggered proactively inside `write_file()`
  whenever the interval has elapsed.
  Remaining open item: `flush_to_disk()` is a stub — writing encrypted artifacts to a physical
  disk destination is not implemented.
- **Impact**: Low for transient scans; moderate for engagements that require on-disk evidence export.
- **Mitigation**: Implement `flush_to_disk()` when durable export is required.

---

## 🧠 2. Detection & Intelligence Gaps

### 2.1 Category Coverage
- **Status**: 78% (Estimated)
- **Gaps**:
    - **Race Conditions**: Only basic signal analysis is implemented; no active multi-threaded exploitation.
    - **AI Surface**: The `ai_surface` category has minimal probes (mostly endpoint discovery).
    - **Business Logic**: Most business logic tests rely on generic JSON mutations rather than flow-aware state machine analysis.
- **Impact**: Blind spots in sophisticated application logic vulnerabilities.

### 2.2 False Positive Reduction
- **Status**: Partial — local per-node feedback loop; shared mesh-wide repository planned
- **Gap**: Semantic deduplication clusters finding families correctly, but the feedback loop (analyst
  FP marks rolling back into the pattern store) operates locally on each mesh node only. A
  centrally shared FP-pattern repository backed by Redis with mesh-wide pub/sub sync has not been
  deployed, so the same FP category may be triaged independently on multiple nodes.
- **Impact**: Analyst triage burden is replicated across the mesh for recurring false-positive types.
- **Mitigation**: Centralize the FP-pattern repository in Redis with mesh-wide pub/sub synchronization.

---

## 🖥️ 3. Frontend & Dashboard Gaps

### 3.1 Unimplemented Routes
- **Status**: Partial — pages and routing are implemented; minor feature gaps remain per page.
- **Details**:
  - `/risk-score` — page component (`RiskScorePage.tsx`) is routed in `App.tsx`; factor card
    and trend-chart are present, but the 3D instanced breakdown of CSI sub-graphs is not yet
    built. A dedicated e2e spec (`risk-score.spec.ts`) exists.
  - `/findings-timeline` — page scaffold present; no dedicated e2e test file yet.
  - `/target-comparison` — page present; the cross-run comparison API endpoint is still under
    development, so the page currently shows fixture data.
  - `/cache-management` — admin page is rendered and mounted; `POST /api/bloom/reconcile`
    trigger wiring in the UI is the remaining gap.
- **Impact**: Limited observability for advanced risk metrics; three of four pages are usable today
  and the fourth is a thin wrapper pending an API hookup.

### 3.2 Real-time Synchronization
- **Status**: Beta
- **Gap**: Occasional state flicker when switching between SSE and WebSocket logs.
- **Impact**: Minor UX degradation during high-throughput phases.

---

## 🧪 4. Testing & Quality Gaps

### 4.1 Integration Testing
- **Status**: Moderate
- **Gap**: Many core modules (`GhostActor`, `Chameleon`) have robust unit tests but lack end-to-end integration tests that simulate full node failure and recovery.
- **Impact**: Regression risk in distributed failover logic.

### 4.2 Benchmark Realism
- **Status**: Synthetic
- **Gap**: `BENCHMARK.md` focuses on synthetic URL generation. No real-world, high-entropy corpus is used for performance baseline testing.
- **Impact**: Throughput metrics might not reflect performance on complex, obfuscated web applications.

---

## 🚀 5. Immediate Action Plan

1.  **Refactor Gap Analysis Router**: Transition from mocked metrics to real telemetry (Completed).
2.  **Fix Benchmarking Harness**: Align load test endpoints with the production API (Completed).
3.  **Implement `ROADMAP.md`**: Formalize these gaps into a prioritized development schedule.
4.  **Harden Actor Migration**: Replace simulation with real-world psutil metrics.
