param(
    [switch]$Force
)

# Remove tracked virtualenv and frontend build artifacts from git (safe guard)
# Usage: .\remove_tracked_artifacts.ps1 -Force

if (-not (Test-Path -Path ".git" -PathType Container)) {
    Write-Host "Not a git repository in the current directory. Aborting." -ForegroundColor Yellow
    exit 1
}

$targets = @(".venv314", "frontend/node_modules", "frontend/dist")
$found = $false

foreach ($t in $targets) {
    if (Test-Path -Path $t) {
        $found = $true
        Write-Host "Found $t"
        if ($Force) {
            Write-Host "Untracking $t..."
            git rm -r --cached --ignore-unmatch $t
        } else {
            Write-Host "Dry run: to actually untrack $t re-run this script with -Force"
        }
    } else {
        Write-Host "$t not present, skipping"
    }
}

if (-not $found) {
    Write-Host "No targets found to untrack." -ForegroundColor Yellow
    exit 0
}

if ($Force) {
    git commit -m "chore: remove committed virtualenv and frontend build artifacts" || Write-Host "Nothing to commit"
    Write-Host "Recommend using 'git filter-repo' or BFG to remove files from history if needed." -ForegroundColor Cyan
} else {
    Write-Host "Dry run complete. Rerun with -Force to perform changes." -ForegroundColor Cyan
}
