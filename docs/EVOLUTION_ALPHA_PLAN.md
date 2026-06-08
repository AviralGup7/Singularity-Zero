# Singularity-Zero: Evolution Alpha - Development Roadmap

This document lists development phases by their honest current status.
Claims here are aligned with the implementation status table in
docs/architecture.md.  Status reflects the state of the main branch at
the time of this update.

| Phase | Description | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Metric-Aware Balancing & Proactive Actor Migration | **In Progress** | Single-node actor runtimes are functional. Distributed actor migration across nodes is not implemented. |
| **Phase 2** | Autonomous Exploitation Engine (AEVE) Verification | **Implemented** | Exploitation engines, safe-exploit wrapper, and rollback manager are functional. WASM-sandboxed PoC execution is not yet connected to wasmtime. |
| **Phase 3** | 3D Attack-Chain Visualizer & Telemetry Micro-Batching | **Implemented** | Dashboard with 3D attack-graph rendering and telemetry streaming is functional. |
| **Phase 4** | WAL State Compaction & GhostVFS Key Rotation | **Partial** | WAL and circuit breaker are functional. GhostVFS AES-GCM encrypted RAM-primary storage is not implemented as described (uses Python bytearray + secure_wipe). |
| **Phase 5** | Continuous Self-Learning & Tag Threshold Tuning | **Implemented** | Nuclei tag optimizer, FP watchlist, and active-learning feedback loop are functional. Optional XGBoost/scikit-learn deps may not be installed; fallback to scikit-learn LogisticRegression is standard. |
| **Phase 6** | Automated Compliance & Regulatory GRC Reporting | **Implemented** | HTML, SARIF, compliance, SLA, VRT reporting is functional. Ticketing (Jira/ServiceNow/DefectDojo) is planned but not shipped. |
| **Phase 7** | Multi-Tenant Isolation (TenantContext & Keys Scoping) | **Implemented** | Redis namespacing and RBAC are functional. Distributed multi-node tenant isolation across a mesh is not implemented. |
| **Phase 8** | Supply Chain Integrity (Provenance & Dependency Locks) | **Implemented** | Nuclei template SHA-256 verification and Ed25519 manifest signing are functional. |
| **Phase 9** | Closed-Loop Exploit Remediation Re-Scan Firewall | **Implemented** | Remediation cooldown + original payload replay logic is functional. |
| **Phase 10** | OpenAPI Spec validation, Plugin Scaffold, cstp doctor | **Implemented** | `cstp` CLI entry point replaces the old `cyber` name. OpenAPI schema sync is functional. |
| **Phase 11** | WCAG 2.2 AA Playwright audits & CSRF Propagation | **Planned** | Playwright workflow fuzzer exists; dedicated WCAG audits are not yet implemented. |

---

### Outstanding Work (as of this revision)

- Ticket-creation integration (Jira, ServiceNow, DefectDojo) is scaffolded as `ticket_creators.py` but wired execution is pending.
- Secrets scanning plugin for response bodies/headers/JS bundles exists as `src/analysis/checks/passive/secrets_scanner.py` and is awaiting broader pipeline integration.
- `intelligence/swarm/`, `intelligence/ml/marl_simulation.py`, and `intelligence/ml/llm_service.py` remain research prototypes and are not wired into the active scan pipeline.
- GraphQL mutation / alias-stacking / persisted-query-hijacking active testing is a gap in the engine catalog.
- Authenticated multi-role credential-rotation scanning is not implemented.
- `detection/` is a thin facade over `analysis/` and remains; merging is planned but not started.

