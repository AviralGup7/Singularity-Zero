# Glossary

Key terms and concepts used in the Singularity-Zero Cyber Security Test Pipeline.

## A
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
- **Polymorphic Chameleon**: A real-time evasion engine that constantly mutates HTTP request signatures (headers, casing, ordering) to bypass behavioral Web Application Firewalls (WAFs).

## S
- **Semantic Deduplication**: The process of using vector-space Cosine Similarity to identify and group vulnerabilities that are functionally identical, ignoring superficial text differences.
- **state_delta**: A dictionary emitted by a stage runner. 
  > **CRITICAL RULE**: The orchestrator applies deltas using CRDT logic. Collections are perfectly synchronized via Vector Clocks.

## V
- **Vector Clock**: A logical clock used in the CRDT engine to track the causal history of state updates, preventing "stale write" corruption in distributed environments.

## W
- **WAL (Write-Ahead Log)**: A durable Redis Stream where every state transition is recorded before it is applied to the pipeline context, enabling perfect crash recovery.
