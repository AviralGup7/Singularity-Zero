"""Audit script: search for 10 specific data-handling bug patterns in src/."""

import os
import re

src = r"D:\cyber security test pipeline - Copy\src"
results = {}


def scan(pattern, label):
    pat = re.compile(pattern)
    hits = []
    for root, dirs, files in os.walk(src):
        for f in files:
            if not f.endswith(".py"):
                continue
            fp = os.path.join(root, f)
            with open(fp, "rb") as fh:
                raw = fh.read()
            lines = raw.decode("utf-8", errors="surrogateescape").splitlines(True)
            for i, ln in enumerate(lines, 1):
                if pat.search(ln):
                    rel = fp.replace(src + "\\", "")
                    hits.append("  " + rel + ":" + str(i) + ": " + ln.strip())
    results[label] = hits


scan(r"json\.loads\(", "1_json.loads")
scan(r"json\.load\s*\(", "2_json.load")
scan(r"\.get\([^,)]+,\s*\[\]", "3_dict_get_default_list")
scan(r"setdefault\([^,)]+,\s*\[\]", "4_setdefault_empty_list")
scan(r"next\([^,]+,\s*None\)", "5_next_gen_none")
scan(r"filter\(None,", "6_filter_none")
scan(r"\bsum\s*\(", "7_sum")
scan(r"\b(max|min)\s*\(", "8_max_min")
scan(r"\blist\s*\(\s*\w+\s*\)", "9_list_var")

# Pattern 4b: unassigned list comprehension on its own line
pat_lc = re.compile(r"^\s*\[.+for\b.+in\b.+\]\s*$")
hits4b = []
for root, dirs, files in os.walk(src):
    for f in files:
        if not f.endswith(".py"):
            continue
        fp = os.path.join(root, f)
        with open(fp, "rb") as fh:
            raw = fh.read()
        lines = raw.decode("utf-8", errors="surrogateescape").splitlines(True)
        for i, ln in enumerate(lines, 1):
            if pat_lc.match(ln):
                rel = fp.replace(src + "\\", "")
                hits4b.append("  " + rel + ":" + str(i) + ": " + ln.strip())
results["4b_unassigned_list_comp"] = hits4b

# Augment pattern-9 hits with the inner variable name
hits9 = results.get("9_list_var", [])
display9 = []
for h in hits9:
    m2 = re.search(r"list\s*\((\w+)\)", h.split(":", 2)[-1])
    inner = m2.group(1) if m2 else "?"
    display9.append(h + "  [var=" + inner + "]")
results["9_list_var"] = display9

# Print results
order = [
    "1_json.loads",
    "2_json_load",
    "3_dict_get_default_list",
    "4_setdefault_empty_list",
    "4b_unassigned_list_comp",
    "5_next_gen_none",
    "6_filter_none",
    "7_sum",
    "8_max_min",
    "9_list_var",
]

for key in order:
    hits = results.get(key, [])
    lbl_map = {
        "1_json.loads": "1. json.loads() — no try/except",
        "2_json.load": "2. json.load() encoding risk",
        "3_dict_get_default_list": "3. dict.get(key, []) mutable default",
        "4_setdefault_empty_list": "4. setdefault(key, []) mutable default",
        "4b_unassigned_list_comp": "4b. Unassigned list comprehension",
        "5_next_gen_none": "5. next(gen, None) silences side-effect item",
        "6_filter_none": "6. filter(None, iterable) drops falsy values",
        "7_sum": "7. sum() on possibly non-numeric values",
        "8_max_min": "8. max()/min() on possibly empty sequence",
        "9_list_var": "9. list(var) where var is a dict",
    }
    lbl = lbl_map.get(key, key)
    if key in ("7_sum", "8_max_min"):
        filtered = []
        for h in hits:
            code = h.split(":", 2)[-1] if h.count(":") >= 2 else h
            if re.search(r"\bif\b|\bor\b|\band\b", code):
                continue
            filtered.append(h)
        if not filtered:
            filtered = ["  (none flagged — all guarded or ternary)"]
        hits = filtered
    print("=== " + lbl + " ===")
    for h in hits:
        print(h)
    print()
