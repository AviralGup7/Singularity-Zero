#!/usr/bin/env bash
# Download ProjectDiscovery scanner binaries (nuclei, httpx, subfinder)
# into .tools/bin/ — these are NOT committed to git.
#
# Usage:
#   bash scripts/download-tools.sh
#
# Requires: Python 3.10+, internet access

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "[*] Downloading scanner binaries to .tools/bin/ ..."
cd "$ROOT_DIR"
python -m src.core.utils.bin_downloader 2>/dev/null || {
    # Fallback: call the setup function directly
    python -c "
from src.core.utils.bin_downloader import setup_all_tools
from pathlib import Path
results = setup_all_tools(console_print=True)
failed = [k for k, v in results.items() if v is None]
if failed:
    print(f'\n[!] Failed to install: {\", \".join(failed)}')
    exit(1)
print('\n[✓] All scanner binaries installed successfully.')
"
}

echo "[*] Verifying installations..."
for tool in nuclei httpx subfinder; do
    bin=".tools/bin/${tool}"
    [ -f "$bin.exe" ] && bin="$bin.exe"
    if [ -f "$bin" ]; then
        echo "  [✓] $tool: $bin"
    else
        echo "  [✗] $tool: NOT FOUND"
    fi
done
