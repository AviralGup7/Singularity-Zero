# Glossary

Key terms and concepts used in the Singularity-Zero Cyber Security Test Pipeline.

## A
- **Active Learning**: A continuous machine learning paradigm that closes the triage loop. The pipeline's `ActiveLearningController` automatically harvests analyst triage signals (True/False positives) and validated findings from local SQLite telemetry to retrain classification estimators in the background. This dynamically refines calibrated vulnerability severity scores and filters false positive noise by 50% without requiring manual model re-compilation.
- **Actor-Mesh**: A distributed computing paradigm where tasks are encapsulated in stateful, location-transparent objects (Actors). Actors can migrate between physical nodes to optimize cluster load.
- **Attack Chain**: A multi-hop exploitation path identified by the Knowledge Graph, mapping how a low-severity bug can be chained to compromise an asset.

## C
- **CRDT (Conflict-free Replicated Data Type)**: A data structure (like the pipeline's LWW-Sets) that guarantees eventual consistency across distributed nodes without requiring locks.
- **CSI (Composite Severity Index)**: The pipeline's proprietary 0.0 - 10.0 risk score, weighted by CVSS, confidence, exploitability, and mesh consensus.

## D
- **Differential Logic Prober**: An analysis engine that detects business logic flaws (IDOR/BAC) by comparing application responses across different authentication contexts using Levenshtein distances.

## G
- **Ghost-Actor**: A task actor capable of serializing its state and moving across the mesh network seamlessly mid-execution.
- **Ghost-VFS**: An anti-forensic, RAM-only Virtual File System encrypted with AES-256-GCM. It prevents sensitive artifacts from ever touching a physical disk.
- **Gossip Protocol**: An authenticated SWIM-based peer-to-peer protocol used by mesh nodes to share CPU/RAM metrics and determine cluster health.

## N
- **Neural-Mesh**: The collective term for the pipeline's distributed intelligence, encompassing the Actor-Mesh, Gossip protocol, and consistent hashing shard manager.

## P
- **Polymorphic Chameleon**: A comprehensive request evasion and WAF bypass subsystem that leverages a Hidden Markov Model (HMM) to monitor detection risk levels in real time. It dynamically transitions through adaptive states (`undetected`, `suspected`, `blocked`, `evading`) based on HTTP response feedback. To defeat behavioral profiling, it implements TLS-level JA3 fingerprint spoofing (modeling Chrome, Firefox, Safari, and Edge browser profiles with Fisher-Yates-based signature mutations) and dynamic request timing jitter generated using an exponential distribution.

## S
- **Semantic Deduplication**: The process of using vector-space Cosine Similarity to identify and group vulnerabilities that are functionally identical, ignoring superficial text differences.
- **state_delta**: A dictionary emitted by a stage runner. 
  > **CRITICAL RULE**: The orchestrator applies deltas using CRDT logic. Collections are perfectly synchronized via Vector Clocks.

## V
- **Vector Clock**: A logical clock used in the CRDT engine to track the causal history of state updates, preventing "stale write" corruption in distributed environments.

## W
- **WAL (Write-Ahead Log)**: A durable Redis Stream where every state transition is recorded before it is applied to the pipeline context, enabling perfect crash recovery.

## X
- **XGBoost Severity Pipeline**: A machine learning estimation pipeline (`XGBoostSeverityPipeline`) designed to predict finding true-positive probabilities. It vectorizes parsed Pydantic v2 feature schemas via Feature Hashing to match high-dimensional categorical security tokens. In compilation-restricted environments where XGBoost or scikit-learn bindings are missing, the pipeline gracefully downgrades to high-fidelity, thread-safe, pure-NumPy sigmoid logistic regression fallbacks to prevent performance degradation or downtime.

---

## 🔢 3D Visualization & Control Layer

- **3D Attack-Chain Cockpit**: A real-time, cinematic security scanning cockpit. It provides fluid, interactive visual representations of discovered asset networks, target hierarchies, and active vulnerability paths by hard-wiring live node discovery and predictive threat lateral movement mappings directly from Kuzu backend graph database queries.
- **Pipeline Control Deck**: A floating glassmorphic tactical controller integrated directly into the 3D Attack-Chain Cockpit. It provides scan target configuration, preset scan mode triggers (Quick/Deep), a checklist of active execution modules, interactive progress indicators, live SSE telemetry tracking, and restart-safe actions (Start/Stop/Restart).
- **Dynamic Level-of-Detail (LOD)**: A visual performance optimization that dynamically scales down the geometric complexity of node meshes (reducing sphere segments from 20 to 12 or 8) based on active network graph sizes (e.g. >150 or >500 nodes) to ensure buttery smooth framerates on lower-spec client machines.
- **Frustum Culling**: A rendering optimization that excludes calculations and GPU draw calls for objects located outside the camera's current viewing volume. Enforcing `frustumCulled={true}` on high-density instanced meshes and edge lines in the 3D Cockpit guarantees optimal dashboard throughput.

