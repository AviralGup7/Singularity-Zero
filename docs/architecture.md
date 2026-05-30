# Project: Singularity-Zero Architecture

This document defines the high-resilience, distributed execution model of the Cyber Security Test Pipeline. The system operates as a **Ghost-Actor Mesh**—a self-organizing, hardware-accelerated autonomous entity designed for infinite scale and zero silent failures.

---

## 🏗️ Core Principles: 'Singularity-Zero'

### 1. The 'Ghost' Execution Plane (Actor-Mesh)
- **Location-Transparent Actors**: Tasks are encapsulated as stateful Actors managed via a **custom, native asyncio-based Actor model** (completely replacing the legacy `pykka` library dependency while preserving full Pykka-compatible API interfaces to guarantee zero contract breakage). If a node experiences heavy load, actors serialize their entire state, including compaction budgets, applied WAL IDs, and dynamic logic functions (using `cloudpickle`-based `mesh_marshal_pickle`), migrating to colder nodes mid-execution. Background tasks execute on thread-isolated event loops, wrapping communication thread-safely via custom `ActorRef` / `ActorFuture` proxies, and support unified exception handling and direct thread-join protections for graceful shutdowns.
- **Distributed Consensus & Sharding**: The mesh uses an authenticated SWIM-based Gossip protocol (HMAC-SHA256). A deterministic Bully algorithm elects shard leaders, and targets are distributed using Consistent Hashing.
- **CRDT State Engine**: All critical pipeline data (subdomains, URLs, findings) are stored in Conflict-free Replicated Data Types using **Hybrid Logical Clock (HLC) LWW-Sets**. Every state update preserves causal consistency with a constant $O(1)$ logical clock size instead of unbounded Vector Clocks. Tombstone compaction runs under AIMD budgeting, accelerated by a high-speed compiled Cython radix sort (`_state_cython.pyx`) with a robust pure-Python fallback.
- **Durable Ledger & Circuit Breaker (WAL)**: All state transitions are committed to the write-ahead log using a physical dual-commit protocol. Deltas are logged concurrently to a Redis Stream and a local Append-Only File (AOF). All Redis command streams are wrapped by an active **Circuit Breaker** pattern (CLOSED, OPEN, HALF_OPEN). If the Redis link drops or times out, the circuit trips to `OPEN`, immediately redirecting all operations to local AOF and SQLite-backed queues with zero thread blockage. Nodes automatically replay and reconcile missed deltas using the local ledger once the Redis link heals. Disk-level durability is guaranteed via explicit buffer flushes and `os.fsync()` commits.
- **Tamper-Evident Audit Chain**: Administrative actions and sensitive API calls are recorded in a cryptographic audit ledger. Each entry contains an HMAC-SHA256 hash of the payload plus the previous entry's hash, creating an immutable chain-of-custody that can be verified via the dashboard.
- **Mesh-wide Intelligence Sync**: Employs a Redis-backed Pub/Sub channel (`mesh.learning.fp_patterns`) to instantly propagate analyst-flagged False Positives across the entire cluster. This ensures that a single triage event on one node auto-suppresses redundant findings cluster-wide.
- **Temporal Key Rotation & Hardening (Ghost-VFS)**: To minimize the exposure window of anti-forensic scan artifacts, Ghost-VFS automatically rotates its AES-GCM encryption keys every 4 hours. All RAM-stored data is re-encrypted on the fly. Rotation uses a pre-decryption validation phase and safe rollbacks to ensure zero data loss on failure, while derived and session keys are stored as mutable `bytearray` objects and zeroed out directly in RAM using `secure_wipe` after usage.

### 2. Cognitive-Logic Analysis
- **Differential Logic Prober**: A high-speed State-Machine Fuzzer that compares endpoint responses across different authentication contexts using Levenshtein distance, automatically detecting IDOR and BAC vulnerabilities.
- **Lateral Movement Graph**: Integrates the `Kuzu` Graph Database to link subdomains, URLs, and findings into Attack Chains, predicting multi-hop exploitation paths (Kill-Chains).
- **Semantic Intelligence**: Finding deduplication uses vector-space Cosine Similarity via NumPy to group functionally identical security signals, bypassing rigid regex constraints.
- **Cognitive-Logic Flow Probing**: Automatically discovers multi-request sequences (e.g., checkout flows) and models them as state transitions. The engine attempts to "break" these transitions by injecting out-of-order requests or manipulating state-dependent tokens (IDs, UUIDs), detecting high-level business logic flaws that atomic scanners miss.
- **Hardware-Isolated WASM Validation**: The **AEVE** engine executes proof-of-concept payloads within restricted WASM sandboxes (`wasmtime`). This provides hardware-level memory and CPU isolation, ensuring that even zero-day PoC logic cannot compromise the pipeline nodes while transitioning finding status from 'Candidate' to 'Verified TP'.
- **XGBoost & Active Learning Severity Engine**: Replaces traditional static scoring models with an industrial-grade **XGBoost and scikit-learn** machine learning pipeline (`XGBoostSeverityPipeline`). The pipeline vectorizes high-dimensional categorical features (vulnerability category, target host, parameter types, module names) using a constant-space `FeatureHasher` (128 slots). A thread-safe `ModelVersionRegistry` manages active model versions, telemetry health checks, and autonomous rollbacks, while the `ActiveLearningController` continuously extracts feedback and outcome signals from the telemetry database to trigger live retraining loops in post-scan hooks. To prevent adversarial feedback poisoning, the controller enforces **defense-in-depth protection policies**: (a) requiring a minimum threshold of $N \ge 3$ independent analyst confirmations for a "false positive" before it is used in retraining, and (b) calculating a dynamic "feedback quality score" and quarantining anomalous bursts (e.g. 5+ FPs marked within 60s) for administrative review. Incorporates high-fidelity, pure-NumPy Logistic Regression fallbacks to ensure zero-downtime inference in environments without compiled binary packages.
- **Calibrated Severity Model Cold-Start Resilience**: The `CalibratedSeverityModel` dynamically calibrates raw machine learning model probabilities. To ensure robustness under cold-start conditions (such as fresh installations or empty telemetry tables where category and parameter support counts are zero), the calibration layer automatically falls back to a global true-positive rate prior (defaulting to `0.5`) instead of zeroing out. This guarantees that new, high-value findings are never silently dropped during early-stage pipeline executions.
- **Robust Threat & Attack Graph Bridge**: The threat graph and attack chain compiler (`build_attack_graph`) features native input normalization. It dynamically identifies and normalizes input formats, seamlessly supporting both direct list-of-dictionary structures (e.g., raw endpoint lists retrieved from APIs) and dictionary-mapped intelligence items. This eliminates silent drops, access-pattern errors, or `AttributeError` crashes across REST controllers and background execution threads.
- **GNN Attack Path Prediction & RL Probe Selection**: Employs deep structural graph learning combined with reinforcement learning target planning. Computes dense node embeddings on the attack graph (representing targets, endpoints, findings, and severities) using a zero-dependency, pure-NumPy 2-layer Graph Convolutional Network (GCN). The symmetric normalized adjacency matrix is computed as $\tilde{A} = D^{-1/2}(A + I)D^{-1/2}$ to enable robust information flow. Pairwise cosine similarity between node embeddings predicts unseen attack path transitions and pivots. Simultaneously, a Q-learning agent (`ProbeSelectionRLAgent`) ranks and recommends optimal active scanner probe execution sequences (SQLi, CSRF, JWT, fuzzing campaigns, etc.) matching target endpoint states (APIs, authenticated endpoints, parameterized fields) with dynamic, reward-driven Q-table updates.
- **Active Parameter Fuzzer Campaign**: A grammar-based and mutation-guided HTTP parameter fuzzer (`FuzzingOrchestrator`) executing active campaigns in the scan stage. Features custom mutation strategies: bit-flipping on raw byte blocks, boundary value injections (handling numeric ranges, complex nested JSON formats, and unique ID types), and custom dictionary template expansions. Guarantees closed-loop learning by recording response status codes and bucketed length bands (100-byte steps) as coverage feedback. Detects unhandled server exceptions (HTTP 500), SQL/execution error stack trace leaks, and structural authentication bypasses to uncover deep application-level logic flaws.
- **Threat Intelligence & MISP Feed Correlation**: Features an asynchronous threat actor and indicator of compromise (IoC) correlation plane. The `MISPClient` subclassing `BaseFeedConnector` utilizes `httpx` to perform non-blocking REST searches (`/attributes/restSearch`) against external MISP threat sharing instances. Discovered target subdomains, IPs, and external infrastructure indicators are dynamically cross-referenced against MISP events, VirusTotal, and AlienVault OTX feeds. Auto-correlates IoCs with known threat actor footprints, CVEs, and active campaign context to calculate real-time reputation scores and dynamically enrich scan findings.
- **Adaptive Nuclei Tag Optimizer & Config Mutation**: Implements a self-learning loop via the `NucleiTagOptimizer` (`src/learning/nuclei_tag_optimizer.py`). Computes per-tag precision, recall, and F1 statistics over telemetry outputs to adaptively override template configurations. Telemetry adaptations are automatically computed, merged, and persisted into a two-generation ledger (`config.adaptive.json` and `config.adaptive.ledger.json`). Threshold Tuner calibrations are validated pre-scan, and dynamic KPIs are served directly to the dashboard Learning tab (`GET /api/learning/kpis`).
- **Collaborative AI Swarm (Red Team Mesh)**: The `SwarmOrchestrator` manages multiple specialized role-based `AgentNode` actors. These actors negotiate targets, discovered scopes, and vulnerabilities, synchronously gossiping and merging state CRDTs under Vector-Clocked HLC sets to ensure zero collision, seamless horizontal load balancing, and causal consistency across the mesh network.



### 3. Stealth & Anti-Forensics
- **Polymorphic Chameleon**: A real-time evasion engine that mutates request characteristics (header ordering, casing, noise headers) and timing behavior. Employs a Hidden Markov Model (HMM) to transition between states (undetected, suspected, blocked, evading) based on response behavior, dynamically adapting JA3 TLS browser fingerprints and injecting human-like exponential timing delays.
- **Deep Reinforcement Learning (DRL) Evasion Model**: An active, online PPO policy-gradient neural network (`PPOEvasionModel`) that replaces the traditional HMM. It maps active observations (OBS_SUCCESS, OBS_BLOCK, OBS_CHALLENGE) to a four-dimensional action space (delay scales, ja3 profiling, http/2 header mutations), learning optimal parameters dynamically based on environmental feedback rewards. Incorporates greedy argmax selection during execution for state stability, and zero-out probability safeguards that prevent premature transitions to the undetected state when WAF triggers are active.

- **Ghost-VFS (Volatile Virtual File System)**: An anti-forensic, RAM-primary virtual file system using AES-256-GCM encryption. While the active storage plane resides entirely in volatile RAM (and is permanently purged on power-off or self-destruction), checkpoints and replicated actor states may be compressed and flushed to physical disk for failover resilience. When the `--replication` flag is active, workers write encrypted differential snapshots to local media to ensure seamless cluster checkpointing and cold-start actor hydration, with strict path traversal checks enforced on all flush paths.
- **Cyber Vault**: Target secrets and API keys are stored in a PBKDF2/AES-GCM secured vault, decrypted strictly in volatile memory.

### 4. Hardware Acceleration
- **SIMD Processing**: URL filtering and string analysis are offloaded to vectorized NumPy routines, enabling the processing of millions of URLs in milliseconds.
- **Binary Marshalling**: Zero-copy state transfers across the mesh utilizing `msgpack` for maximum network throughput.
- **Probabilistic Bloom Mesh**: Cluster-wide URL membership testing leverages MurmurHash3-backed Neural Bloom Filters, saving gigabytes of shared RAM.
- **Bloom-Aware Smart Cache Routing**: Smart routing in `CacheManager` queries the active Bloom filter on the read paths (`get` and `exists`). If a key is absent, the read immediately bypasses L2 (SQLite/Redis) and L3 (File) database/file storage backends, returning a cache miss to maximize cluster throughput.
- **Bloom Reconciliation Plane**: Nodes publish MessagePack Bloom snapshots over Redis pub/sub on `BLOOM_SYNC_INTERVAL_SEC`; vector clocks reject stale snapshots and compatible filters merge by packed-bit OR.
- **Tiered Sandboxing (WASM & Process Isolation)**: The platform enforces a tiered sandboxing strategy. **WebAssembly (WASM) Sandboxing** is the primary isolation mechanism for untrusted proof-of-concept verification (AEVE) and untrusted binary scanners, executing them within a hardware-isolated WebAssembly runtime (`wasmtime`) to block host kernel access. Meanwhile, dynamically loaded Python plugins (Dynamic Plugin SDK) leverage a **Process-Based & AST Validation Sandbox**, which parses the plugin source with AST analysis to reject forbidden imports/dynamic primitives and executes the loader in a separate, disposable child process with restricted I/O channels.

---

## 🖥️ UI / UX Synchronization
The dashboard acts as a **Real-Time Mesh Command Center**:
- **Action Buffer Engine**: Employs a 100ms micro-batching reducer to prevent UI flicker and race conditions during massive telemetry bursts.
- **High-Performance Virtualization**: Uses `react-virtuoso` to render 100,000+ log lines and findings at a steady 60 FPS.
- **Off-Main-Thread Processing**: Heavy filtering and sorting of findings execute via Web Workers.
- **Zod Contract Guards**: Strict schema validation at the API boundary ensures silent schema drift is instantly caught.
- **Instanced 3D Rendering**: The Security Cockpit utilizes `THREE.InstancedMesh` and GPGPU layouts to render 50,000+ nodes in a single draw call.
- **Interactive Request Replay**: Supports real-time "Replay with Diff" for finding verification. Enables analysts to modify headers, auth-modes, and payloads with side-by-side behavioral change detection.
- **Finding Intelligence**: Integrated collaborative notes and threaded analyst commentary for each security finding, synced via SSE.
- **Bloom Mesh Health Tile**: The dashboard polls `/api/bloom/health` for per-node memory, element count, false-positive probability, saturation history, and admin-triggered reconciliation.
- **Interactive Sandbox & Time-Travel Proxies**: Leverages the FastAPI `sandbox_service.py` layer to orchestrate and proxy ephemeral container environments. Analysts can view timeline state snapshots for every pipeline milestone and open secure, isolated xterm.js terminals directly from the dashboard to perform manual validations with zero local configuration.


---

## 🔐 Platform Hardening & Governance

The platform features strict governance and defense-in-depth mechanisms to protect concurrent client operations and secure the automated supply chain:

### 1. Multi-Tenant Key Namespacing, Playbook & Pub/Sub Isolation
- **Thread/Async-Safe Context**: Utilizes a context-variable based `TenantContext` model employing Python `contextvars` to dynamically propagate tenant scopes down the request life cycle in multi-threaded/async environments.
- **Redis Partitioning**: The `RedisClient` automatically intercepts command parameters and registered Lua script arguments, prepending the active `tenant_id` to prevent cross-contamination in shared queues and learning repositories. Direct connections (like `RedisFPRepository`) dynamically namespace key prefixes by the active context `tenant_id`.
- **Pub/Sub Crosstalk Prevention**: `MeshSync` pub/sub channel names are dynamically namespaced by `tenant_id` to prevent multi-tenant logic crosstalk.
- **RBAC Scoping Boundaries**: FastAPI auth dependencies inject tenant claims into user `Principal` schemas, which are evaluated by router access controls to strictly scope all target lists, findings, jobs, execution logs, SSE telemetry, and control states (e.g. stop/restart).
- **Playbook & Header Profile Isolation**: Scopes `nuclei` template execution paths and `Chameleon` evasion header profiles by `tenant_id` to ensure zero concurrent scan crosstalk.

### 2. Supply Chain & Pipeline Integrity
- **Template Cryptographic Verification**: Gated at scanner startup, Nuclei templates are audited using SHA-256 checks and verified against a signed JSON manifest using an Ed25519 public key. Compromised templates immediately halt execution.
- **Dynamic OpenAPI Spec & Docs Sync**: `scripts/validate_openapi.py` compiles the active FastAPI OpenAPI schema dynamically at validation time. It enriches the spec with top-level `x-ai-metadata` and path-level `x-ai-` tags (including the remediation verify endpoint) and automatically synchronizes the machine-readable YAML block in `docs/api-reference.md`. In CI, it fails if committed docs drift from the active schema, supporting `--write` to easily regenerate/sync.
- **Continuous Quality Gates**: The CI pipeline (`ci.yml`) executes mandatory validation gates to prevent regressions:
  - **Dependency Lockdown**: Enforces rigid double-equals (`==`) version pinning in configurations to prevent raw range operator compromises.
  - **SBOM Drift comparison**: Differs CycloneDX software bills of materials against the secure baseline to block new package vulnerabilities.
  - **WCAG 2.2 AA Accessibility Audit**: Evaluates templates and frontend assets to prevent visual layout or focus ring violations.
  - **OpenAPI Schema Check**: Asserts OpenAPI specification structure, required properties, and type variations to catch contract breaks.
  - **Secret Attestation**: Scans static dist bundles and source code to block hardcoded API keys or private keys.

### 3. Closed-Loop Exploit Drift Detection
- **Stateless Correlation Engine**: Implements the Jaccard similarity drift engine, which canonicalizes attack graph node features, edges, and chain links. Structural similarity scores below `0.8` declare path drift, flagging new exposures or successfully closed chains.

### 4. GRC Compliance Scoring
- **Maturity scoring**: Assigns weights (`PASS=100`, `PARTIAL=70`, `AT_RISK=40`, `FAIL=0`) to regulatory controls based on findings, calculating an overall GRC score mapped to distinct maturity bands (`FAIL` if under 50% or if any critical findings exist).
- **Remediation SLA Tracking & Auto-Escalation**: The `SLATracker` engine enforces strict time-to-fix SLAs (Critical = 14 days, High = 30 days) on security findings. Any overdue or breached findings trigger instant, auto-escalating alert workflows through `NotificationManager` sending telemetry payloads directly to Slack, Microsoft Teams, or custom webhooks. Active breaches and MTTR metrics are calculated across tenant boundaries and exposed via the high-fidelity `GET /api/reports/sla/trending` telemetry endpoint for real-time compliance cockpit dashboard rendering.

### 5. Double-Submit Cookie Anti-CSRF
- **Stateless Verification**: State-altering endpoints (`POST`, `PUT`, `DELETE`, `PATCH`) are hardened using double-submit cookie matching. Browser requests must match the `csrf_token` cookie and `X-CSRF-Token` header. Bearer token and custom API-key integrations are dynamically exempted from CSRF policies.

### 6. Priority Queue Aging and Decay (Starvation Evasion)
- **Exponential Boost Decay**: To prevent dynamic correlation priority boosts from infinitely inflating or starving lower-priority tasks, `ScanTarget` calculates its `effective_priority` using an exponential decay factor (120-second half-life) applied strictly to the boosted portion of the priority.
- **Wait-Time Aging Bonus**: A monotonically increasing aging factor (0.01 per wait second) is applied to all unscanned targets, ensuring that starved, low-priority targets eventually get scheduled.
- **Max-Heap Stability**: The queue's `pop()` and `peek()` routines dynamically refresh the bids of all remaining targets and trigger `heapq.heapify` under lock, maintaining strict max-heap sorting order.

### 7. Remediation Re-Scan Firewall
- **Remediation Verification**: The `RemediationScanner` (`src/execution/remediators/remediation_scanner.py`) leverages the Autonomous Exploitation & Verification Engine (`AEVE`) to re-test remediated findings using their original payload within memory-isolated environments.
- **API Verify Router**: Maps the `POST /api/remediated/{finding_id}/verify` endpoint, which executes the remediation check, persists updated states (`REMEDIATED` or `UNREMEDIATED`) to disk, and updates a secure, Redis-tracked **adaptive 72-hour cooldown** to prevent endpoint abuse.

### 8. Recurring False-Positive Watchlist
- **Regression Watchlist Management**: The `FPWatchlistManager` (`src/recon/fp_watchlist.py`) serializes analyst-confirmed `FALSE_POSITIVE` findings to a persistent `<output>/regression-watchlist.json` file on every run completion. De-duplicated URL templates are extracted, and `check_reemergence()` dispatches elevated alerts via the `NotificationManager` if a regression is detected.



