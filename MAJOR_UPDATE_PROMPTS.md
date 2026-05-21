# MAJOR UPDATE PROMPTS — Singularity-Zero Pipeline

Each block below is self-contained and copyable. Every prompt starts with `/goal`.
Scope is broad and generalised — only the objective and the affected code areas are given; implementation details are left entirely to the AI executing the prompt.

---

```
/goal Build an ML-powered vulnerability severity scoring engine across the entire src/intelligence/, src/analysis/intelligence/, and src/recon/ subtree that replaces any and all current hand-crafted NumPy/rule-based severity heuristics with a trained model pipeline. The AI is free to choose the model architecture, feature set, training strategy, and serving mechanism — it only needs to ensure every security finding emitted by the pipeline carries a statistically grounded severity score that calibrates against historical true-positive and false-positive rates stored in the findings database. Touch every file from recon discovery through to the HTML report artefact in src/reporting/.
```

---

```
/goal Rewrite the Ghost-Actor Mesh actor migration and cold-start recovery subsystem spanning src/core/frontier/ghost_actor.py, src/core/frontier/state.py, src/core/frontier/wal.py, and src/core/frontier/proc_pool.py so that an interrupted long-running scan can survive total node failure and resume from its last consistent CRDT snapshot without losing or duplicating any finding or state transition. The AI is free to redesign the snapshot format, the WAL replay strategy, the compaction budget, and the migration handshake protocol as long as the result demonstrably handles cold-start, warm-rejoin, and full-cluster-restart recovery paths. Leave a written evidence trail in docs/.
```

---

```
/goal Implement a production-grade WAF evasion effectiveness benchmark and telemetry layer integrated across src/core/frontier/chameleon.py, src/core/frontier/marshaller.py, src/analysis/active/, and src/dashboard/fastapi/ so that the pipeline can measure, track, and visualise how effectively it evades each WAF product it encounters in the wild. The AI is free to invent the benchmark methodology, choose the metrics, redesign the evasion sampling strategy, and build the dashboard charts — the only constraint is that the result gives analysts a trustworthy, actionable view of evasion performance per-target and per-session via the React frontend.
```

---

```
/goal Overhaul the entire recon → analysis → execution → reporting DAG pipeline instrumentation so that every stage, sub-stage, and individual check emits structured telemetry that can be replayed, re-aggregated, and visually inspected end-to-end in the frontend dashboard. The AI is free to redesign the event schema, choose the serialisation format, redesign the SSE/WebSocket streaming path, refactor the LiveTerminalFeed and VirtualizedFindingsList components, and overhaul the dashboard Charts and Timeline pages — as long as the end-to-end flow from a single recon subdomain discovery to its appearance on the findings timeline page is fully observable and debuggable from the dashboard without touching the backend logs.
```

---

```
/goal Create a universal plugin SDK and dynamic-loading framework spanning src/core/frontier/plugins/, src/analysis/plugins/, src/execution/validators/validators/, and src/core/plugins/ that allows third-party security check authors to drop a single Python file into a watched directory and have it auto-discovered, validated, sandboxed, registered, and exposed to the frontend scan-presets UI — all without a pipeline restart or a code change in the core. The AI is free to design the plugin manifest schema, the sandboxing strategy (process-isolated, WASM, or hybrid), the validation pipeline, the hot-reload watcher, the frontend plugin-progress grid wiring, and the CapabilityManifest auto-generation in src/core/capabilities.py — as long as the result is a documented, working plugin system.
```

---

```
/goal Build a compliance-ready automated report generation and attestation engine across src/reporting/ that transforms every pipeline run into a standards-compliant finding report (treating HTML generation, PDF export, JSON structured output, CI-friendly machine-readable SBOM, compliance-attestation PDF signature, and dashboard-linked report versioning as a single unified problem). The AI is free to redesign the report page model, pick the templating engine, choose the PDF generation library, design the attestation signature chain, and redesign the reporting DAG in src/reporting/pipeline.py — as long as every run produces a signed, verifiable, standards-aligned report artefact stored in the pipeline output store and visible in the React frontend report library page.
```

---

```
/goal Replace the current reactive priority queue and job scheduling subsystem in src/decision/priority_queue.py, src/infrastructure/scheduling/, src/infrastructure/execution_engine/, and src/infrastructure/queue/ with a multi-objective bidding and scheduling engine that balances exploitability, business criticality, analyst SLAs, resource contention, bloom-mesh saturation, and historical scan velocity into a single coherent dispatch ordering. The AI is free to redesign the bidding protocol, the scheduler loop, the resource-pool accounting, and the queue worker protocol — as long as the end result produces measurably better time-to-first-finding and time-to-critical-finding on large multi-thousand-target scans compared to the current implementation.
```

---

```
/goal Design and build a real-time collaborative triage workflow layer spanning src/dashboard/fastapi/, src/websocket_server/, src/learning/, src/reporting/, and the entire frontend component subtree under frontend/src/components/ that allows multiple security analysts to triage, annotate, escalate, and close findings simultaneously on the same pipeline run with real-time presence indicators, cursor-position broadcasting, conflict-free note merging, and a persistent audit chain of every triage action. The AI is free to design the real-time protocol (SSE, WebSocket, or hybrid), choose the merge strategy, redesign the FindingComments and ChainOfCustodyViewer components, wire the mesh-wide FP-pattern repository, and build the analyst-presence indicator — as long as the result works end-to-end from any analyst browser to any other analyst browser with zero manual refresh required.
```

---

```
/goal Build a native 3D attack-chain visualisation cockpit inside the existing React frontend under frontend/src/components/ (primarily AttackChainVisualizer.tsx, ChainOfCustodyViewer.tsx, and any new components under frontend/src/components/charts/) that reads the lateral movement graph stored by src/intelligence/graph/threat_graph.py (Kuzu graph DB) and renders an interactive, navigable 3D node-link diagram of the full kill-chain for each pipeline run — showing subdomain → URL → finding → lateral-edge relationships with health bars, severity colouring, analyst hover-tooltips, drill-down-to-finding navigation, and real-time streaming updates as new nodes are added by the pipeline. The AI is free to redesign the Kuzu cypher query layer, the REST/SSE API surface, the Three.js instanced rendering strategy, the frontend camera controls, the zoom/pan/focus interaction model, and the surrounding dashboard layout — as long as the result gives a single analyst a complete, navigable mental model of the attack surface of a large target in under 60 seconds of interaction.
```

---

```
/goal Deprecate and rebuild the entire fuzzing, payload generation, and active scan execution layer spanning src/fuzzing/, src/analysis/active/, src/core/frontier/wasm.py, src/execution/, src/core/frontier/chameleon.py, and src/core/frontier/plugins/ so that every active check has a typed manifest declaring its I/O contract, its required capabilities, its expected execution budget, and its encoding of results — and every such check runs in an isolated execution context (process or WASM) with a hard time-budget wall enforced by a revocable OS-level kill-signal. The AI is free to redesign the payload generator architecture, pick the isolation mechanism, redesign the plugin manifest schema, build the capability query API, and refactor every existing active check module to conform — as long as the end result guarantees that no malformed, infinite-looping, or malicious check payload can ever crash or corrupt the pipeline worker process that hosts it.
```

---

```
/goal Implement a hardened credential and secret management overlay spanning src/core/frontier/vault.py, src/infrastructure/security/encryption.py, src/infrastructure/security/auth/, src/core/frontier/ghost_vfs.py, and src/core/frontier/wasm.py so that every API key, scanning credential, third-party scanner token, and WAF-evasion parameter stored by the pipeline is encrypted at rest using Argon2id + AES-256-GCM with automatic key rotation, audit-logged access, zero-in-memory-plaintext-after-use, and a sealed-integrity sealed-bundle export format for air-gapped CI/CD runners. The AI is free to redesign the vault keystore hierarchy, choose the rotation schedule strategy, redesign the integration with Ghost-VFS, and refactor every call-site that currently passes credentials as plain text — as long as the result follows cryptographic best practice and every credential access is auditable in the chain-of-custody viewer.
```

---

```
/goal Reduce the end-to-end false-positive rate of the entire pipeline by 50% relative to the current baseline by training or tuning ML-based signal quality filters that operate on the findings emitted by every analysis, detection, execution, and intelligence stage. The AI is free to redesign the FP signal pipeline, retrain the model, rewrite the FPTracker in src/learning/, refactor the reporting sections that render finding confidence, and build the frontend false-positive triage UX — as long as the result gives security analysts a faster, less noisy triage experience and produces measurably fewer false findings per 1000 real findings in a controlled golden-set evaluation stored in tests/fixtures/.
```

---

```
/goal Build an autonomous self-healing pipeline controller that monitors the health of every pipeline stage, queue depth, worker process, bloom-mesh node, and frontend dashboard connection in a running scan and can automatically trigger corrective actions — restart a crashed worker, rebalance actors across nodes, re-fetch stuck stage timeouts, flush an overflowing bloom filter, roll back a bad model version, or escalate to analyst alerting — without any manual intervention. Touch src/pipeline/, src/infrastructure/queue/, src/infrastructure/execution_engine/, src/core/frontier/ghost_actor.py, src/core/frontier/bloom_mesh.py, src/intelligence/ml/registry.py, src/infrastructure/notifications/, and src/dashboard/fastapi/. The AI is free to design the health metric schema, the controller loop, the corrective-action registry, the alert-routing policy, and the dashboard health tile — as long as the result keeps long-running multi-day scans operational without operator intervention.
```

---

```
/goal Rewrite the API security testing and request-replay framework in src/api_tests/ and the corresponding ReplayInterface.tsx in the frontend so that analysts can take any recorded finding request, modify headers, auth modes, payloads, and query parameters in the browser, re-submit the modified request against the live target with a single click, and see a side-by-side behavioural diff highlighting exactly what changed. The AI is free to redesign the replay API contract, refactor the baseline-variant comparison logic in src/api_tests/apitester/baseline_variant.py, redesign the RunDiffViewer.tsx component, add server-side request-mutation middleware, and wire result streaming through the SSE pipeline — as long as the result is a fully working, zero-surprises request replay and diff experience in the browser.
```

```
