"""Targeted BUG8 check: sorted(iterable) without key= — is iterable a dict_values/dict_items/dict_keys?"""

import os
import re

base = r"D:\cyber security test pipeline - Copy\src"
targets = {
    "recon": os.path.join(base, "recon"),
    "analysis": os.path.join(base, "analysis"),
    "learning": os.path.join(base, "learning"),
}

# sorted(x) without key= — look for .values(), .keys(), .items()
pat = re.compile(r"\bsorted\s*\(\s*(\w+)\.(values|keys|items)\s*\(\s*\)\s*\)")

hits = []
for label_t, root in targets.items():
    if not os.path.isdir(root):
        continue
    for r2, dirs, files in os.walk(root):
        for f in files:
            if not f.endswith(".py"):
                continue
            fp2 = os.path.join(r2, f)
            with open(fp2, "rb") as fh:
                lines = fh.read().decode("utf-8", errors="surrogateescape").splitlines(True)
            for i, ln in enumerate(lines, 1):
                if pat.search(ln):
                    rel = fp2.replace(base + os.sep, "")
                    hits.append("  " + rel + ":" + str(i) + ": " + ln.strip())

print("=== BUG8 sub-type: sorted(dict.values/keys/items) without key= ===")
print(str(len(hits)) + " hits")
for h in sorted(hits):
    print(h)
print()

# Also check sorted(iterable) where iterable is set()
pat2 = re.compile(r"\bsorted\s*\(\s*(\w+)\s*\)")
hits2 = []
for label_t, root in targets.items():
    if not os.path.isdir(root):
        continue
    for r2, dirs, files in os.walk(root):
        for f in files:
            if not f.endswith(".py"):
                continue
            fp2 = os.path.join(r2, f)
            with open(fp2, "rb") as fh:
                lines = fh.read().decode("utf-8", errors="surrogateescape").splitlines(True)
            for i, ln in enumerate(lines, 1):
                m = pat2.search(ln)
                if m:
                    var = m.group(1)
                    if var and var[0].isupper():
                        continue  # skip constant names
                    rel = fp2.replace(base + os.sep, "")
                    hits2.append("  " + rel + ":" + str(i) + "  [var=" + var + "] " + ln.strip())

print("=== BUG8 broad: sorted(var) without key= ===")
print(str(len(hits2)) + " hits (first 50 shown)")
for h in sorted(hits2)[:50]:
    print(h)
print()
print("=== DONE ===")
