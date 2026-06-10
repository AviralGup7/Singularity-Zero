# Getting Started & Development Guide

This guide covers environment setup, contribution guidelines, and debugging recipes.

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python 3.12+** (Required)
- **Node.js 18+** (For the React dashboard)
- **Go** (For recon tools)
- **Docker & Compose** (For containerized deployment)

### 2. Environment Setup
```bash
git clone <repo-url> cyber-pipeline
cd cyber-pipeline
python3 -m venv .venv  # Python 3.12 or newer required
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -e ".[dev]"
```

### 3. Basic Configuration
```bash
cp configs/config.example.json configs/config.json
cat configs/scope.example.txt  # See configs/scope.example.txt for multi-line and wildcard formats
echo "example.com" > scope.txt
```

### 4. Multi-Tenant Scoping (Local Development)
To test and develop under a multi-tenant context:
- Set `ENABLE_API_SECURITY=true` in your `.env` file to enable auth token checks globally on the dashboard API and to activate multi-tenant role and tenant boundaries.
- Include the `X-Tenant-ID` header on requests (e.g. `X-Tenant-ID: client_alpha`) to automatically scope Redis keys and findings paths.
- For security header requirements and CSRF Double-Submit token specifications, see [API Reference - Global Security Headers](api-reference.md#global-security-governance-headers).


### 5. Running Your First Scan
```bash
# Verify installation with the system doctor
cyber system doctor

# Verify installation with a dry-run
cyber scan run --config configs/config.json --scope scope.txt --dry-run

# Run a real scan
cyber scan run --config configs/config.json --scope scope.txt
```

### 6. Starting the Dashboard & Background Queue Worker
```bash
# Recommended: Start both in a single command
cyber launch

# Or separately:
# 1. Start the Dashboard Backend
cyber start dashboard --port 8000

# 2. Start a Queue Worker Node
cyber start worker --concurrency 2

# 3. Start the Frontend (Dev mode)
cd frontend && npm install && npm run dev
```

---

## 🌍 Environment Variables

The system relies on environment variables for configuration. To avoid ambiguity, the pipeline uses a centralized manifest.

> **Mandatory Reference**: See [Environment Variables Reference](environment-variables.md) for the complete list of supported variables, defaults, and descriptions.

---

## 🛠️ Required External Tools

The pipeline orchestrates several specialized tools. Install them automatically via `cyber system setup` or manually via `go install`:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **subfinder** | Subdomain discovery | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | Live host probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **katana** | Web crawling | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| **nuclei** | Template scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **gau** | URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |

For quick local deployment of dependencies, simply run:
```bash
cyber system setup
```

---

## 💻 Development Workflow

### Standards
- **Formatting**: `ruff format .`
- **Linting**: `ruff check . --fix`
- **Typing**: `mypy .`
- **Testing**: `pytest`

### Local-Mesh Joining
Workers can register themselves with Redis to join a distributed queue scan context:
```bash
cyber start worker --queue security-pipeline --concurrency 4
```

### 📱 Standalone Sub-Node Setup (Android / Termux / Low-Resource)
For low-resource Android devices running Termux, or remote Linux systems where you don't want a heavy installation, you can spin up a lightweight, completely compilation-free worker node using our single-line bootstrap installer. This installs only Python, the pure-Python Redis client, pre-compiled Go binaries, and a single standalone worker script.

Run the following bootstrap command in Termux (or any compatible terminal):
```bash
curl -sSL -o setup_lite.sh "https://raw.githubusercontent.com/AviralGup7/Singularity-Zero/main/setup_lite.sh?t=\$(date +%s)" && chmod +x setup_lite.sh && ./setup_lite.sh
```

> [!NOTE]
> The `?t=$(date +%s)` cache-buster ensures you always get the latest hotfixes immediately without waiting for GitHub CDN caching (which defaults to a 5-minute TTL).

Once installed, connect the sub-node to the PC backplane:
```bash
python -m src.infrastructure.queue.worker_lite --redis-url redis://<YOUR_PC_IP>:16379/0
```


---

## 🔍 Debugging

### Debugging a Stage
Run the orchestrator synchronously for easier stepping:
```python
import argparse
from pathlib import Path
from src.pipeline.services.pipeline_flow import run_pipeline
from src.core.config.loader import load_config

cfg = load_config(Path("configs/config.json"))
run_pipeline(
    cfg.to_dict(),
    ["example.com"],
    output_dir="output/debug",
    args=argparse.Namespace(),
)
```

### Database
Manage migrations with Alembic:
- `alembic upgrade head`
- `alembic revision --autogenerate -m "description"`

