import type { ModuleOption } from '../types/api';

export interface ModuleDependency {
  requires?: string[];
  incompatibleWith?: string[];
}

const MODULE_DEPENDENCIES: Record<string, ModuleDependency> = {
  active_scanner: {
   
    requires: ['url_crawler'],
  },
  auth_scanner: {
   
    requires: ['url_crawler'],
  },
  api_fuzzer: {
   
    requires: ['url_crawler'],
  },
  parameter_discovery: {
   
    requires: ['url_crawler'],
  },
  xss_scanner: {
   
    requires: ['parameter_discovery'],
  },
  sqli_scanner: {
   
    requires: ['parameter_discovery'],
  },
  ssrf_scanner: {
   
    requires: ['parameter_discovery'],
  },
  path_traversal_scanner: {
   
    requires: ['parameter_discovery'],
  },
  csrf_scanner: {
   
    requires: ['url_crawler'],
  },
  idor_scanner: {
   
    requires: ['parameter_discovery', 'auth_scanner'],
  },
  subdomain_enum: {
   
    incompatibleWith: ['active_scanner'],
  },
  port_scanner: {
   
    incompatibleWith: ['subdomain_enum'],
  },
};

export interface DependencyWarning {
  type: 'missing' | 'incompatible';
  module: string;
  moduleLabel: string;
  relatedModules: string[];
  relatedLabels: string[];
  message: string;
}

export function checkModuleDependencies(
  selectedModules: Set<string>,
  moduleOptions: ModuleOption[],
): DependencyWarning[] {
   
  const warnings: DependencyWarning[] = [];
   
  const labelMap = new Map(moduleOptions.map(m => [m.name, m.label]));

  for (const mod of selectedModules) {
    const dep = Reflect.get(MODULE_DEPENDENCIES, mod) as ModuleDependency | undefined;
    if (!dep) continue;

    const modLabel = labelMap.get(mod) || mod;

    if (dep.requires) {
      for (const req of dep.requires) {
        if (!selectedModules.has(req)) {
          const reqLabel = labelMap.get(req) || req;
          warnings.push({
            type: 'missing',
            module: mod,
            moduleLabel: modLabel,
   
            relatedModules: [req],
   
            relatedLabels: [reqLabel],
            message: `${modLabel} requires ${reqLabel} to function properly.`,
          });
        }
      }
    }

    if (dep.incompatibleWith) {
      for (const inc of dep.incompatibleWith) {
        if (selectedModules.has(inc)) {
          const incLabel = labelMap.get(inc) || inc;
          warnings.push({
            type: 'incompatible',
            module: mod,
            moduleLabel: modLabel,
   
            relatedModules: [inc],
   
            relatedLabels: [incLabel],
            message: `${modLabel} is incompatible with ${incLabel}.`,
          });
        }
      }
    }
  }

  return warnings;
}

export function autoResolveDependencies(
  selectedModules: Set<string>,
  _moduleOptions: ModuleOption[],
): Set<string> {
  // NOTE: _moduleOptions is currently unused.
  // This function only adds required modules, never removes incompatible ones.
  // To fully resolve dependencies, also check incompatibleWith.
  const resolved = new Set(selectedModules);
  let changed = true;

  while (changed) {
    changed = false;
    for (const mod of resolved) {
      const dep = MODULE_DEPENDENCIES[mod];
      if (dep?.requires) {
        for (const req of dep.requires) {
          if (!resolved.has(req)) {
            resolved.add(req);
            changed = true;
          }
        }
      }
    }
  }

  return resolved;
}
