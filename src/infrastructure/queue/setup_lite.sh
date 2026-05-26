#!/usr/bin/env bash

# ==============================================================================
# Singularity-Zero: Standalone Sub-Node Bootstrap Installer
# This script configures Termux/Android to act as a lightweight mesh worker
# with zero codebase cloning or C/Rust library compilation.
# ==============================================================================

set -eo pipefail

echo -e "\033[1;32m"
echo "  🌌 Singularity-Zero Standalone Sub-Node Setup"
echo "  --------------------------------------------"
echo -e "\033[0m"

# 1. Detect if Termux environment is active
if [ -d "/data/data/com.termux/files/usr" ]; then
    echo "[*] Termux environment detected. Updating package directories..."
    pkg update -y
    
    echo "[*] Installing Python..."
    pkg install python -y
else
    echo "[*] Standard Linux environment detected."
    if ! command -v python3 &>/dev/null; then
        echo "[!] Python3 is not installed. Please install it using your package manager."
        exit 1
    fi
fi

# 2. Install lightweight redis client dependency
echo "[*] Installing pure-Python Redis client..."
pip install redis

# 3. Download standalone worker_lite.py script
echo "[*] Downloading standalone worker_lite.py script..."
LITE_WORKER_URL="https://raw.githubusercontent.com/AviralGup7/Singularity-Zero/main/src/infrastructure/queue/worker_lite.py"
curl -sSL -o worker_lite.py "$LITE_WORKER_URL"

if [ ! -f "worker_lite.py" ]; then
    echo "[✗] Error: Failed to download worker_lite.py from GitHub."
    exit 1
fi

# 4. Trigger automated Go tool binary setup
echo "[*] Launching Go tool setup sequence..."
python worker_lite.py --setup

echo -e "\033[1;32m"
echo "[✓] Standalone Sub-Node Setup Completed!"
echo "----------------------------------------------------------------"
echo "To start your sub-node and connect it to your PC's mesh cockpit:"
echo ""
echo "  python worker_lite.py --redis-url redis://<YOUR_PC_IP>:6379/0"
echo "----------------------------------------------------------------"
echo -e "\033[0m"
