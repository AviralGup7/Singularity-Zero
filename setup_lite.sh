#!/usr/bin/env bash

# ==============================================================================
# Singularity-Zero: Standalone Sub-Node Bootstrap Installer
# This script configures Termux/Android to act as a lightweight mesh worker
# with zero codebase cloning or C/Rust library compilation.
#
# SECURITY: The ``worker_lite.py`` download is now performed over HTTPS with
# an optional SHA-256 integrity check. Operators are strongly encouraged to
# set ``WORKER_LITE_SHA256`` in the environment to a known-good hash of
# the upstream script before running this installer. If the hash does not
# match, the script aborts before any downloaded code is executed.
# ==============================================================================

set -euo pipefail

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
if python3 -c "import redis" &>/dev/null; then
    echo "[*] Redis client is already installed."
else
    echo "[*] Installing pure-Python Redis client..."
    pip install redis
fi

# 3. Download standalone worker_lite.py script
#    SECURITY: the integrity of the downloaded file is verified with a
#    SHA-256 hash when the operator supplies WORKER_LITE_SHA256. Without
#    the env var, the script warns and continues - but the operator
#    should treat that mode as a security downgrade.
echo "[*] Downloading standalone worker_lite.py script..."
LITE_WORKER_URL="https://raw.githubusercontent.com/AviralGup7/Singularity-Zero/main/src/infrastructure/queue/worker_lite.py"
TMP_FILE="$(mktemp -t worker_lite.XXXXXX.py)"
trap 'rm -f "$TMP_FILE"' EXIT
curl --fail --silent --show-error --location --tlsv1.2 --proto '=https' \
    --output "$TMP_FILE" "$LITE_WORKER_URL"

if [ ! -s "$TMP_FILE" ]; then
    echo "[✗] Error: Failed to download worker_lite.py from GitHub." >&2
    exit 1
fi

# 4. Verify integrity of the downloaded file.
if [ -n "${WORKER_LITE_SHA256:-}" ]; then
    echo "[*] Verifying SHA-256 integrity of worker_lite.py..."
    ACTUAL_HASH="$(sha256sum "$TMP_FILE" | awk '{print $1}')"
    if [ "$ACTUAL_HASH" != "$WORKER_LITE_SHA256" ]; then
        echo "[✗] Error: SHA-256 mismatch for worker_lite.py." >&2
        echo "    Expected: $WORKER_LITE_SHA256" >&2
        echo "    Actual:   $ACTUAL_HASH" >&2
        exit 1
    fi
    echo "[✓] SHA-256 verification passed."
else
    echo "[!] WARNING: WORKER_LITE_SHA256 is not set." >&2
    echo "    Downloaded code will be executed WITHOUT integrity verification." >&2
    echo "    To enable verification, set WORKER_LITE_SHA256 to the SHA-256" >&2
    echo "    hash of the upstream worker_lite.py before running this script." >&2
    # Give the operator a chance to abort.
    read -r -p "    Continue without integrity check? [y/N] " reply
    case "$reply" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

mv "$TMP_FILE" worker_lite.py
chmod 0644 worker_lite.py
trap - EXIT

# 5. Trigger automated Go tool binary setup
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
