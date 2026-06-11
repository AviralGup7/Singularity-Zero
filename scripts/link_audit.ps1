import os
import re
import glob

docs_dir = r'D:\cyber security test pipeline - Copy\docs'
files = sorted(set(glob.glob(os.path.join(docs_dir, '*.md')) + glob.glob(os.path.join(docs_dir, '**', '*.md'), recursive=True)))
basename_map = {os.path.basename(f).lower(): f for f in files}

def extract_headings(content):
    headings = []
    for line in content.split('\n'):
        m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if m:
            headings.append(m.group(2).strip())
    return headings

def slugify(text):
    slug = text.lower()
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[\s_]+', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    slug = slug.strip('-')
    return slug

headings_map = {}
for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as fh:
            content = fh.read()
        headings = extract_headings(content)
        headings_map[f] = {slugify(h): h for h in headings}
    except Exception as e:
        print(f'Error reading {f}: {e}')

link_pattern = re.compile(r'\[([^\[]*)\]\(([^)]+)\)')

print('='*80)
print('MARKDOWN LINK AUDIT - docs/')
print('='*80)

results = []

for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except Exception as e:
        print(f'SKIP {f}: {e}')
        continue
    
    links = link_pattern.findall(content)
    for text, target in links:
        if not target or target.startswith('http://') or target.startswith('https://') or target.startswith('/') or target.startswith('#'):
            continue
        if '.md' not in target:
            continue
        
        rel_path = target.split('#')[0]
        anchor = target.split('#')[1] if '#' in target else None
        
        # Try direct path and slash variants
        target_path = os.path.join(docs_dir, rel_path.replace('/', os.sep))
        target_exists = os.path.isfile(target_path)
        if not target_exists:
            target_path2 = os.path.join(docs_dir, rel_path)
            target_exists = os.path.isfile(target_path2)
            if target_exists:
                target_path = target_path2
        
        if not target_exists:
            status = 'BROKEN - FILE NOT FOUND'
        elif anchor is not None:
            if target_path in headings_map:
                if anchor in headings_map[target_path]:
                    status = 'OK'
                else:
                    found = False
                    for s, h in headings_map[target_path].items():
                        if anchor == s:
                            found = True
                            break
                        if anchor.replace('-', ' ').lower() == h.lower():
                            found = True
                            break
                    if found:
                        status = 'OK'
                    else:
                        status = 'BROKEN - ANCHOR NOT FOUND'
            else:
                status = 'OK (no headings)'
        else:
            status = 'OK'
        
        if 'BROKEN' in status:
            available = []
            if target_exists and target_path in headings_map:
                available = list(headings_map[target_path].keys())
            elif target_exists:
                available = ['(target has no headings map)']
            else:
                available = []
            results.append({
                'file': os.path.relpath(f, docs_dir),
                'text': text,
                'target': target,
                'status': status,
                'available': available[:20]
            })

print()
print('BROKEN LINKS:')
print()
for r in results:
    print(f'FILE: {r["file"]}')
    print(f'  LINK: [{r["text"]}]({r["target"]})')
    print(f'  STATUS: {r["status"]}')
    if r['available']:
        print(f'  AVAILABLE ANCHORS: {r["available"]}')
    print()
