import os
import re
import glob

docs_dir = r'D:\cyber security test pipeline - Copy\docs'
files = sorted(set(glob.glob(os.path.join(docs_dir, '*.md')) + glob.glob(os.path.join(docs_dir, '**', '*.md'), recursive=True)))

def robust_slugify(text):
    slug = text.strip().lower()
    slug = re.sub(r'[\s_/]+', '-', slug)
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = re.sub(r'-+', '-', slug)
    slug = slug.strip('-')
    return slug

link_pattern = re.compile(r'\[([^\]]*)\]\(([^#)]+)(?:#([^)]+))?\)')

for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as fh:
            lines = fh.readlines()
    except Exception as e:
        continue
    
    rel_base = os.path.relpath(f, docs_dir)
    for i, line in enumerate(lines, 1):
        matches = list(link_pattern.finditer(line))
        for m in matches:
            text = m.group(1)
            target = m.group(2)
            anchor = m.group(3) if m.group(3) is not None else ''
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
            target_exists = os.path.isfile(target_path_md)
            
            if not target_exists:
                continue
            
            broken = False
            reason = ''
            
            if rel_path_md == 'architecture.md':
                if anchor in ('1-multi-tenant-key-namespacing-playbook--pubsub-isolation', '3-stealth--anti-forensics', '5-sandbox-proxies--time-travel', '-ui--ux-synchronization', '2-cognitive-logic-analysis'):
                    broken = True
                    reason = 'wrong anchor slug'
            
            if rel_path_md == 'commands.md':
                if anchor == '5-system-maintenance--health':
                    broken = True
                    reason = 'wrong anchor slug'
            
            if rel_path_md == 'testing.md':
                if anchor in ('145-automated-quality-gates--pipeline-security-verification', '-automated-quality-gates--pipeline-security-verification'):
                    broken = True
                    reason = 'wrong anchor slug'
            
            if rel_path_md == 'api-reference.md':
                if anchor == '-global-security--governance-headers':
                    broken = True
                    reason = 'wrong anchor slug'
            
            if rel_path_md == 'performance.md':
                if anchor == '-bottleneck-detection--mesh-auto-scaling':
                    broken = True
                    reason = 'wrong anchor slug'
            
            if rel_path_md == 'environment-variables.md':
                if anchor == '':
                    broken = True
                    reason = 'empty anchor'
            
            if broken:
                print(rel_base + ':' + str(i) + ' | ' + reason + ' | [' + text + '](' + target + '#' + anchor + ')'  )

