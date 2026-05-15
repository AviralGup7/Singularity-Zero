<#
Dev start helper for Windows PowerShell

Usage: .\scripts\dev-start.ps1

This script creates a virtual environment (if missing), activates it, installs
development dependencies, and copies the example config to `config.json` if one
is not present. It prints next steps but does not attempt to run the dashboard
or pipeline automatically.
#>

param(
    [string]$VenvPath = ".venv",
    [string]$ConfigExample = "configs/config.example.json",
    [string]$ConfigTarget = "config.json"
)

Write-Host "Starting dev helper..."

if (-not (Test-Path $VenvPath)) {
    Write-Host "Creating virtual environment at $VenvPath"
    python -m venv $VenvPath
}

Write-Host "Activating virtual environment"
& "$VenvPath\Scripts\Activate.ps1"

Write-Host "Installing development dependencies (this may take a while)"
pip install -e .[dev]

if (-not (Test-Path $ConfigTarget) -and (Test-Path $ConfigExample)) {
    Copy-Item $ConfigExample $ConfigTarget
    Write-Host "Copied $ConfigExample to $ConfigTarget. Please edit $ConfigTarget as needed."
}

Write-Host "Dev setup complete. Next steps:"
Write-Host "  - Start the dashboard: cyber-dashboard --port 8000"
Write-Host "  - Run the pipeline: cyber-pipeline --config $ConfigTarget --scope configs/scope.example.txt"
Write-Host "  - Run unit tests: pytest tests/unit -q"
