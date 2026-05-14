$subpackages = @(
    "src/analysis/json",
    "src/analysis/response", 
    "src/analysis/intelligence",
    "src/analysis/behavior",
    "src/analysis/helpers",
    "src/analysis/checks",
    "src/analysis/plugin_runtime",
    "src/analysis/automation",
    "src/detection",
    "src/decision",
    "src/execution",
    "src/intelligence",
    "src/fuzzing",
    "src/reporting",
    "src/learning",
    "src/api_tests",
    "src/websocket_server",
    "src/infrastructure/queue",
    "src/infrastructure/cache",
    "src/infrastructure/execution_engine",
    "src/infrastructure/observability",
    "src/infrastructure/security",
    "src/dashboard",
    "src/dashboard/fastapi",
    "apps",
    "scripts",
    "deploy",
    "frontend/src",
    "tests"
)

foreach ($pkg in $subpackages) {
    if (Test-Path $pkg) {
        $count = (Get-ChildItem $pkg -Recurse -File -Filter "*.py" -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Output "PKG:$pkg FILES:$count"
        if ($count -gt 0) {
            Get-ChildItem $pkg -Recurse -File -Filter "*.py" -ErrorAction SilentlyContinue | ForEach-Object {
                $name = $_.Name
                $len = $_.Length
                Write-Output "  $name ($len bytes)"
            }
        }
    } else {
        Write-Output "PKG:$pkg MISSING"
    }
}
