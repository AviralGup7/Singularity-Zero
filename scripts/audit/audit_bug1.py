"""Find the true BUG1 pattern: .get() result chained directly to .lower()/.strip()/.upper()/.split() without wrapping."""

import os
import re

base = r"D:\cyber security test pipeline - Copy\src"
targets = {
    "recon": os.path.join(base, "recon"),
    "analysis": os.path.join(base, "analysis"),
    "learning": os.path.join(base, "learning"),
}

# Pattern: some_var = some_dict.get("key").<method>  — no str() wrapper
# Covers .lower() .strip() .upper() .split() .startswith() .endswith() .replace()
pat = re.compile(
    r"\.get\(\s*[\'\"][^\'\"]+[\'\"]\s*\)\s*\.\s*(lower|strip|upper|split|startswith|endswith|replace)\b"
)

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
                if pat.search(ln) and "str(" not in ln:
                    rel = fp2.replace(base + os.sep, "")
                    hits.append("  " + rel + ":" + str(i) + ": " + ln.strip())

print("=== BUG1: .get(key).lower/strip/etc. without str() wrapper ===")
print("(" + str(len(hits)) + " hits)")
print()
for h in sorted(hits):
    print(h)
print()
print("=== DONE ===")
