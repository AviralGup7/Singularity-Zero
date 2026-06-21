# Download ProjectDiscovery scanner binaries (nuclei, httpx, subfinder)
# into .tools/bin/ — these are NOT committed to git.
#
# Usage:
#   .\scripts\download-tools.ps1

$ErrorActionPreference = "Stop"
$RootDir = Split-Path $PSScriptRoot -Parent

Write-Host "[*] Downloading scanner binaries to .tools/bin/ ..." -ForegroundColor Green
Set-Location $RootDir

try {
    python -m src.core.utils.bin_downloader 2>$null
} catch {
    python -c @"
from src.core.utils.bin_downloader import setup_all_tools
from pathlib import Path
results = setup_all_tools(console_print=True)
failed = [k for k, v in results.items() if v is None]
if failed:
    print(f'\n[!] Failed to install: {", ".join(failed)}')
    exit(1)
print('\n[✓] All scanner binaries installed successfully.')
"@
}

Write-Host "`n[*] Verifying installations..." -ForegroundColor Cyan
foreach ($tool in @("nuclei", "httpx", "subfinder")) {
    $bin = Join-Path $RootDir ".tools\bin\$tool.exe"
    if (Test-Path $bin) {
        Write-Host "  [✓] $tool" -ForegroundColor Green
    } else {
        Write-Host "  [✗] $tool NOT FOUND" -ForegroundColor Red
    }
}
