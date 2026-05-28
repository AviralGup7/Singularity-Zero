# Glossary

Key terms and concepts used in the Singularity-Zero Cyber Security Test Pipeline.

## A
- **Active Learning**: A continuous machine learning paradigm that harvests analyst triage signals (True/False positives) from SQLite telemetry to retrain classification estimators in the background. See [Architecture - Cognitive-Logic Analysis](architecture.md#2-cognitive-logic-analysis) for active learning details.
- **Actor-Mesh**: A distributed computing paradigm where tasks are encapsulated in stateful, location-transparent, native `asyncio`-based objects (Actors) running on isolated threads. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh) for mesh implementation.
- **Attack Chain**: A multi-hop exploitation path predicted by the lateral graph, mapping how low-severity issues can be chained to compromise critical assets. See [Architecture - Cognitive-Logic Analysis](architecture.md#2-cognitive-logic-analysis).

## C
- **Circuit Breaker**: An architectural resilience pattern that wraps Redis connection streams. If failures occur, it transitions to `OPEN` and redirects operations to SQLite/AOF storage with zero thread blockage. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).
- **CRDT (Conflict-free Replicated Data Type)**: A lock-free data structure (such as our HLC-based LWW-Sets) ensuring eventual state consistency across mesh nodes. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).
- **CSI (Composite Severity Index)**: The pipeline's proprietary 0.0 to 10.0 risk score, dynamically calculated based on CVSS, confidence, exploitability, and mesh consensus. See [Architecture - Cognitive-Logic Analysis](architecture.md#2-cognitive-logic-analysis).

## D
- **Differential Logic Prober**: An active scanning engine that compares application responses across different authentication contexts to detect authorization bypasses (IDOR/BAC). See [Architecture - Cognitive-Logic Analysis](architecture.md#2-cognitive-logic-analysis).

## G
- **Ghost-Actor**: A task actor capable of serializing its entire execution state (and logic function) and migrating dynamically across mesh nodes mid-execution. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).
- **Ghost-VFS**: An anti-forensic, memory-only Virtual File System encrypted with AES-256-GCM that prevents sensitive scan artifacts from touching physical storage. See [Architecture - Stealth & Anti-Forensics](architecture.md#3-stealth--anti-forensics).
- **Gossip Protocol**: An authenticated SWIM-based peer-to-peer protocol used by mesh nodes to share load metrics and monitor cluster health. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).

## H
- **Hybrid Logical Clock (HLC)**: A logical clock combining physical physical time and logical sequence counters to order events causally in constant $O(1)$ space. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).

## N
- **Neural-Mesh**: The collective term for the pipeline's self-organizing P2P distributed intelligence layer. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).

## P
- **Polymorphic Chameleon**: An evasion subsystem leveraging a Hidden Markov Model (HMM) to dynamically mutate request headers, JA3 TLS fingerprints, and inject timing delays to bypass WAF heuristic profiling. See [Architecture - Stealth & Anti-Forensics](architecture.md#3-stealth--anti-forensics).

## S
- **Semantic Deduplication**: A technique that groups functionally identical vulnerability findings using vector-space Cosine Similarity, bypassing rigid signature limitations. See [Architecture - Cognitive-Logic Analysis](architecture.md#2-cognitive-logic-analysis).
- **state_delta**: An incremental state dictionary emitted by a stage runner and merged by the orchestrator using CRDT Hybrid Logical Clocks (HLC). See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).

## W
- **WAL (Write-Ahead Log)**: A durable transactional log of state transitions committed concurrently to both a Redis Stream and a local AOF ledger. See [Architecture - The 'Ghost' Execution Plane](architecture.md#1-the-ghost-execution-plane-actor-mesh).

## X
- **XGBoost Severity Pipeline**: A machine learning pipeline predicting true-positive finding probabilities from validated Pydantic feature schemas, equipped with a pure-NumPy fallback engine. See [Architecture - Cognitive-Logic Analysis](architecture.md#2-cognitive-logic-analysis).

---

## 🔢 3D Visualization & Control Layer

- **3D Attack-Chain Cockpit**: A real-time, interactive visual interface mapping target hierarchies and threat lateral movement directly from Kuzu graph DB queries. See [Architecture - UI / UX Synchronization](architecture.md#-ui--ux-synchronization).
- **Pipeline Control Deck**: A floating glassmorphic controller integrated into the 3D Cockpit to configure scans, view SSE active-stage telemetry, and execute restart-safe control actions. See [Architecture - UI / UX Synchronization](architecture.md#-ui--ux-synchronization).
- **Dynamic Level-of-Detail (LOD)**: A visual performance optimization that scales down geometric complexity of node meshes based on active network graph size to ensure 60 FPS rendering. See [Architecture - UI / UX Synchronization](architecture.md#-ui--ux-synchronization).
- **Frustum Culling**: A rendering optimization that excludes calculations and GPU draw calls for objects located outside the camera's current viewing volume. See [Architecture - UI / UX Synchronization](architecture.md#-ui--ux-synchronization).

