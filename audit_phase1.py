"""Audit phase 1: critical patterns in recon/, pipeline/, exploitation/."""
import os, re, sys

base = r'D:\cyber security test pipeline - Copy\src'
targets = ['recon', 'analysis', 'pipeline', 'exploitation', 'intelligence', 'core', 'decision']

results = {}

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

scan(r'json\.loads\(', 'json.loads')
scan(r'\.get\([^,)]+,\s*\[\]', 'dict_get_default_list')
scan(r'setdefault\([^,)]+,\s*\[\]', 'setdefault_empty_list')
scan(r'next\([^,]+,\s*None\)', 'next_gen_none')
scan(r'filter\(None,', 'filter_none')
scan(r'\blist\s*\(\s*\w+\s*\)', 'list_var')

order = ['json.loads','dict_get_default_list','setdefault_empty_list','next_gen_none','filter_none','list_var']
for k in order:
    hits = results.get(k, [])
    print('=== ' + k + ' (' + str(len(hits)) + ') ===')
    for h in hits:
        print(h)
    if not hits:
        print('  (none)')
    print()
