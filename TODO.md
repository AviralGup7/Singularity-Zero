# Project Roadmap & Implementation Status (TODO)

This document tracks completed architectural milestones, resilience hardening, and planned roadmap items across the Cyber Security Test Pipeline.

---

## ✅ Completed Milestones

### 1. DAG Orchestrator & Recovery Subsystem
- [x] **Actor-Based Asynchronous Scheduling**: Implemented `ActorScheduler` in `src/pipeline/services/pipeline_orchestrator/actor_scheduler.py` with speculative dispatch and dependency resolution.
- [x] **CRDT HLC State Engine**: Implemented LWW-Set CRDTs with Hybrid Logical Clocks in `src/frontier/` and `src/core/frontier/`.
- [x] **WAL Journal Replay & Recovery**: Implemented `--resume-from` and `--wal-replay` (verify/replay/dry-run) backed by dual-commit journals.
- [x] **Wall-Clock Deadline Budgeting**: Added `--max-duration` enforcement in `src/pipeline/services/pipeline_orchestrator/actor_scheduler.py` with `global_deadline_exceeded` stage skipping.

### 2. Resilience & Circuit Breaking
- [x] **Persistent 3-State Circuit Breakers**: Implemented `src/resilience/circuit_breaker.py` with Redis/SQLite state persistence.
- [x] **HTTP 429 Retry-After Handling**: Implemented automatic `Retry-After` header extraction and cancellable sleep backoff in `src/resilience/retry_after.py`.
- [x] **Unified Hierarchical Caching**: Unified cache facade with single-flight request coalescing (`CoalescingCacheWrapper`) in `src/pipeline/unified_cache/` and `src/cache/`.

### 3. Intelligence & Active Learning
- [x] **Closed-Loop Feedback Retraining**: Implemented `src/learning/feedback_loop.py` and `src/learning/finding_deduplicator.py` to auto-suppress recurring false positives.
- [x] **Adaptive Nuclei Tag Optimizer**: Implemented per-tag precision/recall telemetry tracking in `src/learning/nuclei_tag_optimizer.py`.
- [x] **WASM & Process Exploit Sandboxing**: Hardware-isolated PoC validation via `wasmtime` and AST-restricted child process loaders in `src/sandbox/`.

### 4. Real-Time Console & Cockpit
- [x] **React 19 + Tailwind CSS 4 Dashboard**: Upgraded operator console with Zustand state management.
- [x] **3D Threat Graph Cockpit**: Instanced GPU rendering of attack graphs via React Three Fiber and Three.js.
- [x] **High-Throughput Virtualization**: Integrated `react-virtuoso` for smooth 60 FPS rendering of 100k+ log entries.

---

## 🎯 Active & Future Roadmap

- [ ] **Multi-Region Consensus Clustering**: Wire multi-node SWIM gossip consensus with distributed cross-region hash ring sync.
- [ ] **Interactive Remediation Verification Playbooks**: Expanded in-browser auto-remediation workflows with simulated exploit replay.
- [ ] **GNN Lateral Path Prediction Enhancements**: Train graph neural network models on expansive real-world vulnerability topology datasets.
- [ ] **Enhanced Cloud Asset Auto-Discovery**: Add native Azure Resource Graph and GCP Cloud Asset Inventory collectors to `src/recon/cloud_recon/`.
