import os
import re

src = r'D:\cyber security test pipeline - Copy\src'

patterns = [
    (re.compile(r'\.get\([^)]+\)\s*or\s*["\x27]{2}'), 'get_or_empty_str'),
    (re.compile(r'0 or [^N0\.]'), 'zero_or_fallback'),
    (re.compile(r'if .+ == 0 or .+ >='), 'zero_or_ge'),
]

for root, dirs, files in os.walk(src):
    for f in files:
        if not f.endswith('.py'):
            continue
        path = os.path.join(root, f)
        try:
            with open(path, encoding='utf-8') as fh:
                lines = fh.readlines()
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            for pat, label in patterns:
                m = pat.search(line)
                if m:
                    print(f'{path}:{i} [{label}]: {line.rstrip()[:120]}')
                    break
