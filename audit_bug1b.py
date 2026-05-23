"""Find all .get('key') without default value — all targets, recon/analysis/learning."""

import os
import re

base = r"D:\cyber security test pipeline - Copy\src"
targets = {
    "recon": os.path.join(base, "recon"),
    "analysis": os.path.join(base, "analysis"),
    "learning": os.path.join(base, "learning"),
}

# Captures exactly: .get("key") or .get('key') — no second argument
pat = re.compile(r"\.get\(\s*[\'\"][^\'\"]+[\'\"]\s*\)")

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
                raw = fh.read()
            lines = raw.decode("utf-8", errors="surrogateescape").splitlines(True)
            for i, ln in enumerate(lines, 1):
                if pat.search(ln):
                    rel = fp2.replace(base + os.sep, "")
                    hits.append("  " + rel + ":" + str(i) + ": " + ln.strip())

print('=== BUG1-like: .get("key") without default ===')
print(str(len(hits)) + " total hits in recon/analysis/learning")
print()
for h in sorted(hits):
    print(h)
print()
print("=== DONE ===")
