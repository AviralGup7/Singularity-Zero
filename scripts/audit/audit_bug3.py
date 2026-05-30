"""Find bare `return` inside `for` loop (BUG3) — no preceding `yield`, no `if` compound."""

import os
import re

base = r"D:\cyber security test pipeline - Copy\src"
targets = {
    "recon": os.path.join(base, "recon"),
    "analysis": os.path.join(base, "analysis"),
    "learning": os.path.join(base, "learning"),
}

PAT = re.compile(r"\breturn\b")

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
            in_for = 0
            for i, ln in enumerate(lines, 1):
                stripped = ln.strip()
                # Simple tracking: 'for ' increments level, 'def ' or 'class ' resets
                if re.search(r"\b(for|while)\s*\(", ln) or re.match(r"\s*for\b", ln):
                    in_for += 1
                elif re.match(r"\s*def\b|\s*class\b", ln):
                    in_for = 0
                if in_for > 0 and PAT.search(ln):
                    rel = fp2.replace(base + os.sep, "")
                    hits.append("  " + rel + ":" + str(i) + ": " + ln.strip())

print("=== BUG3: bare return inside for loop ===")
print(str(len(hits)) + " total")
for h in sorted(hits):
    print(h)
print()
print("=== DONE ===")
