# Cyber Security Test Pipeline : Singularity-Zero

An industrial-grade, fully autonomous security testing platform engineered at the frontier of human software capability. Designed for infinite horizontal scaling, anti-forensic execution, and polymorphic evasion.

---

## 🌌 Core Innovations: 'Singularity-Zero'

- **Ghost-Actor Mesh**: Location-transparent actors (`pykka`) seamlessly migrate across worker nodes mid-execution to balance cluster load dynamically.
- **Causal State Engine**: Perfect synchronization across the distributed cluster using Vector-Clocked CRDTs (Conflict-free Replicated Data Types) and a Redis-backed Write-Ahead Log (WAL).
- **Anti-Forensic Ghost-VFS**: Volatile, AES-256-GCM encrypted RAM storage. Artifacts never touch physical disk, ensuring true deniability upon power-off.
- **Polymorphic Chameleon**: Real-time request mutation (header order, casing, JA3 simulation) renders the scanner invisible to modern behavioral WAFs.
- **Differential Logic Prober**: High-speed state-machine fuzzing detects IDOR and Authorization Bypass automatically using Levenshtein distance analysis.
- **Lateral Knowledge Graph**: Predicts multi-hop exploitation paths (Kill-Chains) by linking findings in a local `Kuzu` Graph Database.
- **Hardware Acceleration**: Analyzes millions of strings in milliseconds using SIMD-optimized `NumPy` routines and MurmurHash3 Bloom Filters.

---

## ⚡ Quick Start

```bash
# 1. Setup Environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

# 2. Build Frontend (React 18 + Virtuoso + R3F)
cd frontend && npm install && npm run build
cd ..

# 3. Start the Neural-Mesh Infrastructure (Redis required)
export MESH_SECRET="your-secure-gossip-key"
python3 src/cli.py start dashboard --workers 4
python3 src/cli.py start worker --concurrency 10

# 4. Initiate Autonomous Scan
python3 src/cli.py scan run --config configs/config.json --scope configs/scope.txt
```

## 🗺️ System Control
- **Ops Command Center**: Access the React dashboard at `http://localhost:8000/`.
- **Security Cockpit**: Monitor 3D Instanced-Rendered threat graphs and Kuzu-powered Kill-Chains.
- **Mesh Command**: View live Gossip-protocol telemetry, CPU usage, and volatile RAM state across all nodes.

## ⚖️ License
Authorized security testing only. See `LICENSE`.
