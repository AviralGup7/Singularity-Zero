"""Full 12-pattern audit: recon/, analysis/, learning/ only."""

import os
import re

base = r"D:\cyber security test pipeline - Copy\src"
targets = {
    "recon": os.path.join(base, "recon"),
    "analysis": os.path.join(base, "analysis"),
    "learning": os.path.join(base, "learning"),
}

results = {}


def scan(pattern, label):
    pat = re.compile(pattern)
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
    results[label] = hits


# ── BUG1 : .get() without default argument ───────────────────────────────────
# Must be a bare .get(KEY) — no second positional arg, no "key=" keyword
scan(r"\.get\(\s*[\'\"][^\'\"]+[\'\"]\s*\)", "BUG1_get_without_default")

# ── BUG4 : .split()[INDEX] without empty-guard ───────────────────────────────
# .split()[0] when no explicit if guard on same/previous line
scan(r"\.split\(\)\s*\[0\]", "BUG4_split_index_zero")

# ── BUG5 : isinstance without isinstance(..., list) or isinstance(..., dict) ────
# We just list all isinstance so reviewer can judge
scan(r"\bisinstance\s*\(", "BUG5_isinstance")

# ── BUG7 : list(var) where var is not literally [] ────────────────────────────
scan(r"\blist\s*\(\s*\w+\s*\)", "BUG7_list_wrap")

# ── BUG8 : sorted(x, key=…)  ─────────────────────────────────────────────────
scan(r"\bsorted\s*\(", "BUG8_sorted")

# ── BUG10 : dict() with no arguments ─────────────────────────────────────────
scan(r"\bdict\s*\(\s*\)", "BUG10_empty_dict_ctor")

# ── BUG11 : match.group(1) without explicit if guard ─────────────────────────
scan(r"\.group\s*\(\s*1\s*\)", "BUG11_group1")

order = [
    "BUG1_get_without_default",
    "BUG4_split_index_zero",
    "BUG5_isinstance",
    "BUG7_list_wrap",
    "BUG8_sorted",
    "BUG10_empty_dict_ctor",
    "BUG11_group1",
]

for k in order:
    hits = results.get(k, [])
    print()
    print("=" * 70)
    print(f"  {k}  ({len(hits)} hits)")
    print("=" * 70)
    for h in hits:
        print(h)
    if not hits:
        print("  (none)")

print()
print("=== DONE ===")
