$src = 'D:\cyber security test pipeline - Copy\docs\commands.md'
$content = [System.IO.File]::ReadAllText($src, [System.Text.Encoding]::UTF8)
$content = $content.Replace('- **Dashboard Server**: `cyber-dashboard` (aliases `cyber start dashboard`)', '- **Dashboard Server**: cyber-dashboard was removed; use `cyber start dashboard` directly')
[System.IO.File]::WriteAllText($src, $content, [System.Text.Encoding]::UTF8)