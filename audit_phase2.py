"""Audit phase 2: sum/max/min and unassigned list comprehensions."""
import os, re, sys

base = r'D:\cyber security test pipeline - Copy\src'
targets = ['recon', 'analysis', 'pipeline', 'exploitation', 'intelligence', 'core', 'decision']

results = {}

# Unassigned list comprehension
pat_lc = re.compile(r'^\s*\[.+for\b.+in\b.+\]\s*$')
hits_lc = []
for t in targets:
    root = os.path.join(base, t)
    if not os.path.isdir(root): continue
    for r2, dirs, files in os.walk(root):
        for f in files:
            if not f.endswith('.py'): continue
            fp2 = os.path.join(r2, f)
            with open(fp2, 'rb') as fh:
                lines = fh.read().decode('utf-8', errors='surrogateescape').splitlines(True)
            for i, ln in enumerate(lines, 1):
                if pat_lc.match(ln):
                    rel = fp2.replace(base + os.sep, '')
                    hits_lc.append('  ' + rel + ':' + str(i) + ': ' + ln.strip())
results['unassigned_lc'] = hits_lc

def scan(pattern, label):
    pat = re.compile(pattern)
    hits = []
    for t in targets:
        root = os.path.join(base, t)
        if not os.path.isdir(root): continue
        for r2, dirs, files in os.walk(root):
            for f in files:
                if not f.endswith('.py'): continue
                fp2 = os.path.join(r2, f)
                with open(fp2, 'rb') as fh:
                    lines = fh.read().decode('utf-8', errors='surrogateescape').splitlines(True)
                for i, ln in enumerate(lines, 1):
                    if pat.search(ln):
                        rel = fp2.replace(base + os.sep, '')
                        hits.append('  ' + rel + ':' + str(i) + ': ' + ln.strip())
    results[label] = hits

scan(r'\bsum\s*\(', 'sum_calls')
scan(r'\b(max|min)\s*\(', 'max_min_calls')

for k in ['unassigned_lc', 'sum_calls', 'max_min_calls']:
    hits = results.get(k, [])
    if k in ('sum_calls', 'max_min_calls'):
        filtered = []
        for h in hits:
            code = h.split(':', 2)[-1]
            if re.search(r'\bif\b|\bor\b|\band\b', code):
                continue
            filtered.append(h)
        hits = filtered if filtered else ['  (none strictly unguarded)']
    print('=== ' + k + ' (' + str(len(hits)) + ') ===')
    for h in hits:
        print(h)
    print()
