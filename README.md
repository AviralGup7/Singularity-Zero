# Cyber Security Test Pipeline : Singularity-Zero

An industrial-grade, fully autonomous security testing platform engineered at the frontier of human software capability. Designed for infinite horizontal scaling, anti-forensic execution, and polymorphic evasion.

---

## 🌌 Core Innovations: 'Singularity-Zero'

- **Ghost-Actor Mesh**: Location-transparent actors seamlessly migrate across worker nodes mid-execution to balance cluster load dynamically.
- **Causal State Engine**: Perfect synchronization across the distributed cluster using Vector-Clocked CRDTs and Redis-backed Bloom Filter reconciliation.
- **Anti-Forensic Ghost-VFS**: Volatile, AES-256-GCM encrypted RAM storage. Artifacts never touch physical disk, ensuring zero persistent footprint.
- **Closed-Loop Feedback**: An active learning feedback engine running XGBoost and scikit-learn classifiers over Pydantic v2 feature vector schemas. It extracts security analyst triage outcomes and SQLite findings histories to automatically trigger dynamic retraining cycles in the background, updating calibrated severity scores and false positive patterns dynamically between runs.
- **Polymorphic Chameleon**: State-driven evasion using a Hidden Markov Model (HMM) to dynamically transition evasion levels, mutate HTTP/2 header parameters, generate human-like timing delays using exponential distributions, and spoof/mutate JA3 TLS fingerprints across Chrome, Firefox, Safari, and Edge profiles.
- **3D Attack-Chain Cockpit & Control Deck**: A cinema-grade 3D threat cockpit engineered using type-safe React Three Fiber (R3F) and Three.js instanced rendering. Supports real-time node discovery and predictive threat lateral mapping from Kuzu graph databases at 60 FPS via frustum culling and dynamic Level-of-Detail (LOD). Integrates a floating glassmorphic Pipeline Control Deck for target scoping, Quick/Deep presets, module checklist config, active stage polling, and restart-safe controls.
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
