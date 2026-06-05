import ast
import os
import re
from pathlib import Path

ROOT = Path(r"D:\cyber security test pipeline - Copy")
SKIP = {'.venv','.venv-linux','.git','__pycache__','.mypy_cache','.ruff_cache','.pytest_cache','.kilo'}
LEFTover = {'apply_edits.py','apply_fixes_part2.py','apply_safe_close_guard.py','find_bugs.py','patch_remaining.py','start_backend.py','tmp_audit.py'}

results = {k:[] for k in ['unused_imports','unused_vars','unused_args','empty_catch_pass','commented_blocks','unreachable_after_return','debug_leftover','leftover_patch_scripts']}
illegal_chars = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP]
    for fn in filenames:
        if not fn.endswith('.py'):
            continue
        path = Path(dirpath)/fn
        rel = str(path.relative_to(ROOT))
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            text = illegal_chars.sub('', text)
        except Exception:
            continue
        lines = text.splitlines()

        if fn in LEFTover:
            results['leftover_patch_scripts'].append(rel)
            continue

        # commented blocks >=3 consecutive comment lines
        start = None
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if s.startswith('#') and not s.startswith('#!') and len(s) > 1:
                if start is None:
                    start = i
            else:
                if start is not None and (i - start) >= 3:
                    results['commented_blocks'].append((rel, start, i-1, i-start))
                start = None
        if start is not None and (len(lines)-start+1) >= 3:
            results['commented_blocks'].append((rel, start, len(lines), len(lines)-start+1))

        # empty except Exception: pass
        for i in range(len(lines)):
            m = re.match(r'^([ \t]*)except[ \t]+Exception:[ \t]*$', lines[i])
            if m and i+1 < len(lines) and lines[i+1].strip() == 'pass':
                results['empty_catch_pass'].append((rel, i+1, lines[i].rstrip()))

        # unreachable after return
        ret = False
        in_docstring = False
        docchar = None
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if not in_docstring:
                if s.startswith('def ') or s.startswith('class ') or s.startswith('@') or s.startswith('async def '):
                    ret = False
                    continue
                if 'return' in s and not s.startswith('#'):
                    # crude: detect return statement line
                    if re.search(r'(^|[^.\w])return($| )', s):
                        ret = True
                if ret and s and not s.startswith('#'):
                    results['unreachable_after_return'].append((rel, i, s))
                    ret = False
            # skip docstrings is implicit by not matching return / generic

        # debug leftovers
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if any(x in s for x in ['pdb.set_trace()','console.log(','breakpoint()']):
                results['debug_leftover'].append((rel, i, s))

        # AST-based
        try:
            tree = ast.parse(text)
        except Exception:
            continue
        imported = set()
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported.add(a.asname or a.name.split('.')[0])
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    imported.add(a.asname or a.name)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used.add(node.id)
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        used.add(t.id)
        for n in imported:
            if n.startswith('_') or n in {'os','sys','typing','pathlib','json','logging','time','datetime','re','ast','sqlite3','uuid','dataclasses'}:
                continue
            if n not in used:
                results['unused_imports'].append((rel, n))

print('RESULTS')
for k,v in results.items():
    print(f'\\n{k}: {len(v)}')
    for row in v[:30]:
        print(row)
