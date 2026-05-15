$baseDir = "D:\cyber security test pipeline - Copy\src\analysis"
$dirs = "json","response","intelligence","behavior","helpers","checks","plugin_runtime","automation"
foreach ($d in $dirs) {
    $fullPath = Join-Path $baseDir $d
    Write-Host ""
    Write-Host "=== $d ==="
    Get-ChildItem -Path $fullPath -Recurse -File | Sort-Object FullName | ForEach-Object {
        Write-Host "$($_.FullName.Replace($fullPath + '\', '    '))" $([math]::Round($_.Length / 1024.0, 1)) "KB  ($($_.Length) bytes)"
    }
    Write-Host ""
}
