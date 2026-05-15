# Cyber Security Test Pipeline : Singularity-Zero

An industrial-grade, fully autonomous security testing platform engineered at the frontier of human software capability. Designed for infinite horizontal scaling, anti-forensic execution, and polymorphic evasion.

---

## 🌌 Core Innovations: 'Singularity-Zero'

- **Ghost-Actor Mesh**: Location-transparent actors seamlessly migrate across worker nodes mid-execution to balance cluster load dynamically.
- **Causal State Engine**: Perfect synchronization across the distributed cluster using Vector-Clocked CRDTs and Redis-backed Bloom Filter reconciliation.
- **Anti-Forensic Ghost-VFS**: Volatile, AES-256-GCM encrypted RAM storage. Artifacts never touch physical disk, ensuring zero persistent footprint.
- **Closed-Loop Feedback**: A self-improving engine that adjusts scan thresholds and payload strategies based on historical True/False positive telemetry.
- **Polymorphic Chameleon**: Real-time request mutation (header order, JA3 simulation) renders the scanner invisible to modern behavioral WAFs.
- **Risk-Score Engine**: Autonomous 0-10 scoring based on vulnerability density, attack chain depth, and data sensitivity.
- **Hardware Acceleration**: Analyzes millions of strings in milliseconds using SIMD-optimized `NumPy` routines and Neural-Bloom Filters.

---

## ⚡ Quick Start

```bash
# 1. Setup Environment
python3.14 -m venv .venv
source .venv/bin/activate
pip install .

# 2. Build Frontend (React 19 + R3F + Tailwind 4)
cd frontend && npm install && npm run build
cd ..

# 3. Start the Neural-Mesh Infrastructure (Redis required)
python3 src/dashboard/fastapi/main.py --host 0.0.0.0 --port 8000
```

## 🗺️ System Control
- **Ops Command Center**: Access the React 19 dashboard at `http://localhost:8000/`.
- **Security Cockpit**: Monitor 3D Instanced-Rendered threat graphs and autonomous risk scores.
- **Mesh Health**: View live Bloom reconciliation telemetry and Vector-Clocked state across all nodes.

## ⚖️ License
Authorized security testing only. See `LICENSE`.
