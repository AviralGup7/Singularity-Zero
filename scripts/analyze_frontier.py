"""Analyze core/frontier module dependencies."""
import glob
import re
from collections import defaultdict

module_imports = defaultdict(lambda: {'internal': [], 'external': []})

files = glob.glob('src/core/frontier/**/*.py', recursive=True)

for path in files:
    parts = path.replace('\\', '/').split('/')
    idx = parts.index('frontier')
    module = parts[idx+1].replace('.py', '') if idx+1 < len(parts) else '__init__'
    
    try:
        with open(path, encoding='utf-8') as f:
            content = f.read()
            for match in re.finditer(r'from\s+(src\.(\S+?))\s+import', content):
                full_import = match.group(1)
                pkg = match.group(2).split('.')[0]
                
                if 'core.frontier' in full_import:
                    target = full_import.split('frontier.')[1].split('.')[0] if 'frontier.' in full_import else full_import
                    module_imports[module]['internal'].append(target)
                elif pkg in ['execution', 'learning', 'analysis', 'detection', 'recon', 'decision', 'pipeline', 'dashboard']:
                    module_imports[module]['external'].append('DOMAIN:' + pkg)
                elif pkg in ['infrastructure']:
                    sub = full_import.split('.')[2] if len(full_import.split('.')) > 2 else full_import
                    module_imports[module]['external'].append('INFRA:' + sub)
                elif pkg == 'core':
                    module_imports[module]['external'].append('CORE:' + full_import)
    except Exception:
        pass

print('=== MODULE CLASSIFICATION ===')
print()

pure_core = []
infra_dependent = []
domain_dependent = []

for mod, deps in sorted(module_imports.items()):
    all_ext = deps['external']
    has_domain = any('DOMAIN:' in d for d in all_ext)
    has_infra = any('INFRA:' in d for d in all_ext)
    
    if has_domain:
        domain_dependent.append(mod)
    elif has_infra:
        infra_dependent.append(mod)
    else:
        pure_core.append(mod)

print('PURE CORE (no infra/domain deps):')
for m in sorted(pure_core):
    print(f'  {m}')

print()
print('INFRASTRUCTURE-DEPENDENT:')
for m in sorted(infra_dependent):
    deps = [d for d in module_imports[m]['external'] if 'INFRA:' in d]
    print(f'  {m}: {deps}')

print()
print('DOMAIN-DEPENDENT:')
for m in sorted(domain_dependent):
    deps = [d for d in module_imports[m]['external'] if 'DOMAIN:' in d]
    print(f'  {m}: {deps}')

print()
print('=== DEPENDENCY GRAPH ===')
for mod, deps in sorted(module_imports.items()):
    if deps['internal'] or deps['external']:
        print(f'{mod}:')
        if deps['internal']:
            print(f'  internal: {list(set(deps["internal"]))}')
        ext_filtered = [d for d in deps['external'] if not d.startswith('CORE:')]
        if ext_filtered:
            print(f'  external: {list(set(ext_filtered))}')
