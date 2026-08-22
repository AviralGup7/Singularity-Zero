# Getting Started & Developer Guide

This guide walks you through setting up your local environment, installing dependencies, configuring target scopes, and executing your first security scan with the Cyber Security Test Pipeline.

---

## ⚡ Prerequisites

- **Python**: Version `3.13` or newer.
- **Node.js**: Version `20` or newer with `npm`.
- **Go**: Version `1.22+` (Optional, required if building external recon tools from source).
- **Redis**: Recommended for distributed queues, Bloom mesh, and session caching (in-memory fallbacks available for single-node development).
- **Docker & Docker Compose**: Recommended for containerized deployment.

---

## 🚀 Environment Installation

### 1. Clone & Set Up Python Environment
```bash
# Clone the repository
git clone https://github.com/AviralGup7/Singularity-Zero.git cyber-pipeline
cd cyber-pipeline

# Create and activate virtual environment (Python 3.13+)
python3 -m venv .venv
source .venv/bin/activate       # On Windows PowerShell: .venv\Scripts\Activate.ps1

# Install package in editable mode with development dependencies
pip install -e ".[dev]"
```

### 2. Build the React Operator Dashboard
```bash
cd frontend
npm install
npm run build
cd ..
```

### 3. Setup Scanning Tools
Auto-download pre-compiled binaries (`nuclei`, `httpx`, `subfinder`, `katana`, `gau`) to `.tools/bin`:
```bash
cstp system setup
```

---

## ⚙️ Configuration & Target Scoping

### 1. Initialize Configuration Files
```bash
# Copy example configuration templates
cp configs/config.example.json configs/config.json
cp configs/api_keys.example.json configs/api_keys.json
cp .env.example .env
```

### 2. Define Target Scope
Specify the in-scope hostnames or domains in `configs/scope.txt`:
```text
# configs/scope.txt
example.com
*.staging.example.com
api.example.com
```

### 3. Verify Configuration Integrity
Run the system doctor to check for missing dependencies or misconfigured parameters:
```bash
cstp system doctor
```

---

## 🎯 Running Your First Scan

### 1. Launch Operator Cockpit (Dashboard + Worker)
```bash
cstp launch --host 127.0.0.1 --port 8000 --concurrency 2
```
Open your browser to [http://localhost:8000](http://localhost:8000) to access the real-time operator cockpit.

### 2. Run a Command-Line Scan
Execute an active vulnerability scan directly from the terminal:
```bash
# Run validation dry-run (No outbound traffic)
cstp scan run --config configs/config.json --scope configs/scope.txt --dry-run

# Run full production scan
cstp scan run --config configs/config.json --scope configs/scope.txt
```

Scan outputs, finding artifacts, and SARIF reports will be generated in `output/<target_hash>/`.

---

## 🧑‍💻 Development Workflow & Code Quality

- **Format Code**:
  ```bash
  ruff format .
  ```
- **Lint & Fix**:
  ```bash
  ruff check . --fix
  ```
- **Static Typing**:
  ```bash
  mypy src/
  ```
- **Execute Unit Tests**:
  ```bash
  pytest tests/unit/
  ```
- **Execute Integration Tests**:
  ```bash
  pytest tests/integration/
  ```

---

## 📱 Lightweight Termux / Sub-Node Setup

For low-resource Android devices running Termux or remote lightweight edge agents:

```bash
curl -sSL -o setup_lite.sh "https://raw.githubusercontent.com/AviralGup7/Singularity-Zero/main/setup_lite.sh?t=$(date +%s)" && chmod +x setup_lite.sh && ./setup_lite.sh
```

Join the distributed cluster backplane:
```bash
python -m src.infrastructure.queue.worker_lite --redis-url redis://<PC_HOST_IP>:6379/0
```

---

## 📚 Where to Go Next

- [Codebase Map](codebase.md) — Comprehensive guide to all 35 modules in `src/`.
- [Commands Reference](commands.md) — Complete CLI options and flags.
- [Environment Variables](environment-variables.md) — Catalog of system settings.
- [Failure Modes](FAILURE_MODES.md) — Troubleshooting degraded scans and zero-finding reports.
- [Testing & CI](testing.md) — Test architecture and CI test harness.
