import pathlib

FIND_PATH = pathlib.Path(r'D:\cyber security test pipeline - Copy\frontend\src\components\findings\FindingComparisonPanel.tsx')
STORE_PATH = pathlib.Path(r'D:\cyber security test pipeline - Copy\frontend\src\stores\workspaceStore.ts')

FIND_OLD = "  const val = f.cvss_v4_score ?? f.cvss_score ?? (typeof f.cvss === 'number' ? f.cvss : null);\n  return val || 0;\n"
FIND_NEW = "  const val = (f.cvss_v4_score ?? f.cvss_score ?? (typeof f.cvss === 'number' ? f.cvss : null)) || 0;\n  return val;\n"

STORE_OLD = "        getItem: (name) => {\n          const val = safeStorage.get(name);\n          if (val == null) return null;\n          try {\n            return JSON.parse(val);\n          } catch {\n            return val;\n          }\n        },\n        setItem: (name, value) => {\n          safeStorage.set(name, JSON.stringify(value));\n        },\n        removeItem: (name) => {\n          safeStorage.remove(name);\n        },\n"
STORE_NEW = "        getItem: (name: string) => {\n          const val = safeStorage.get(name);\n          if (val == null) return null;\n          try {\n            return JSON.parse(val);\n          } catch {\n            return val;\n          }\n        },\n        setItem: (name: string, value: unknown) => {\n          safeStorage.set(name, JSON.stringify(value));\n        },\n        removeItem: (name: string) => {\n          safeStorage.remove(name);\n        },\n"

def patch(path, old, new):
    text = path.read_text(encoding='utf-8')
    if old not in text:
        return False
    path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
    return True

ok1 = patch(FIND_PATH, FIND_OLD, FIND_NEW)
ok2 = patch(STORE_PATH, STORE_OLD, STORE_NEW)
print('FindingComparisonPanel patched:', ok1)
print('workspaceStore patched:', ok2)
