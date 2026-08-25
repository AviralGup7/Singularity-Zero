"""Find .get(key) [no default] not used in a conditional/boolean context (BUG1 candidate)."""

import os
import re

base = r"D:\cyber security test pipeline - Copy\src"
targets = {
    "recon": os.path.join(base, "recon"),
    "analysis": os.path.join(base, "analysis"),
    "learning": os.path.join(base, "learning"),
}

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
                m = pat.search(ln)
                if not m:
                    continue
                end = m.end()
                # Skip if protected: str() or .lower/... chained directly (handled by other scan)
                # Skip if protected by 'or "..."' within 12 chars after the )
                tail = ln[end : end + 20]
                if "str(" in ln or "or " in tail:
                    continue
                # Skip if the .get() is ONLY used as a boolean test
                # (value in X, if value:)
                # Heuristic: if the line is just 'value = d.get("k")' followed by nothing
                # Actually, we want to flag ONLY: var_lower = response.get("url", "").lower()  — prefer had default
                # Exclude: result = value.get("k")  — result is stored but not used as None-threatening
                # We'll just list them all
                rel = fp2.replace(base + os.sep, "")
                hits.append("  " + rel + ":" + str(i) + ": " + ln.strip())

h = "\n".join(sorted(set(hits)))
out = f"=== BUG1 precursor: .get(key) without default (only no-or, no-str) ===\n{len(hits)} hits\n{h}\n=== DONE ==="
fpath = r"D:\cyber security test pipeline - Copy\bug1_precursor.txt"
with open(fpath, "w", encoding="utf-8") as f:
    f.write(out)
print("Done:", len(hits), "hits, written to", fpath)
