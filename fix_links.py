import os
import re
import glob

docs_dir = r'D:\cyber security test pipeline - Copy\docs'
files = sorted(set(glob.glob(os.path.join(docs_dir, '*.md')) + glob.glob(os.path.join(docs_dir, '**', '*.md'), recursive=True)))

def extract_headings(content):
    headings = []
    for line in content.split('\n'):
        m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if m:
            headings.append(m.group(2).strip())
    return headings

def robust_slugify(text):
    # Match GitHub/CommonMark slug rules
    slug = text.strip().lower()
    # Replace spaces, underscores, and multiple hyphens
    slug = re.sub(r'[\s_/]+', '-', slug)
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = re.sub(r'-+', '-', slug)
    slug = slug.strip('-')
    return slug

headings_map = {}
for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as fh:
            content = fh.read()
        headings = extract_headings(content)
        headings_map[f] = {robust_slugify(h): h for h in headings}
    except Exception as e:
        pass

link_pattern = re.compile(r'\[([^\]]*)\]\(([^#)]*)(?:#([^)]+))?\)')

all_results = []

for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except Exception as e:
        continue
    
    rel_base = os.path.relpath(f, docs_dir)
    links = link_pattern.findall(content)
    for text, target, anchor in links:
        if not target or target.startswith('http://') or target.startswith('https://') or target.startswith('/') or target.startswith('#'):
            continue
        if not target.endswith('.md') and '.md' not in target:
            continue
        
        rel_path = target.strip('/')
        if not rel_path.endswith('.md'):
            rel_path_md = rel_path + '.md'
        else:
            rel_path_md = rel_path
            
        target_path_md = os.path.join(docs_dir, rel_path_md.replace('/', os.sep))
        target_path_base = os.path.join(docs_dir, rel_path.replace('/', os.sep))
        
        target_exists = os.path.isfile(target_path_md) or os.path.isfile(target_path_base)
        if not target_exists:
            target_path = target_path_md
        else:
            if os.path.isfile(target_path_md):
                target_path = target_path_md
            else:
                target_path = target_path_base
        
        if not os.path.isfile(target_path):
            status = 'BROKEN - FILE NOT FOUND'
            available = []
        elif anchor is not None:
            if target_path in headings_map:
                anchor_clean = anchor.strip('-').strip()
                if anchor_clean in headings_map[target_path]:
                    status = 'OK'
                elif robust_slugify(anchor_clean) in headings_map[target_path]:
                    status = 'OK'
                else:
                    status = 'BROKEN - ANCHOR NOT FOUND'
            else:
                status = 'OK (no headings map)'
            available = list(headings_map.get(target_path, {}).keys())
        else:
            status = 'OK'
            available = []
        
        if 'BROKEN' in status:
            all_results.append({
                'file': rel_base,
                'text': text,
                'target': target if anchor is None else target + '#' + anchor,
                'status': status,
                'available': available[:15]
            })

print('Total broken links:', len(all_results))
print()
for i, r in enumerate(all_results, 1):
    print(str(i) + '. FILE: ' + r['file'])
    print('   LINK: [' + r['text'] + '](' + r['target'] + ')')
    print('   STATUS: ' + r['status'])
    if r['available']:
        print('   AVAILABLE: ' + str(r['available']))
    print()
