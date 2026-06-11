"""
Enhanced coverage analysis for the cyber security test pipeline.
"""

import ast
import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path(r"D:\cyber security test pipeline - Copy")
SRC = ROOT / "src"
TESTS = ROOT / "tests"

# =============================================================================
# 1. Build source module map (dotted path -> absolute path)
# =============================================================================
src_modules = {}
for p in SRC.rglob("*.py"):
    if p.name == "__init__.py":
        continue
    rel = p.relative_to(SRC)
    dotted = ".".join(rel.with_suffix("").parts)
    src_modules[dotted] = p

# =============================================================================
# 2. Build test module map (file -> list of imported modules)
# =============================================================================
test_files = []
for p in TESTS.rglob("test_*.py"):
    if "archive" in str(p) or str(p).endswith("__pycache__"):
        continue
    test_files.append(p)

# Also include files matching test_*.py
imported_test_modules = defaultdict(set)  # dotted module name -> set of test files
for tp in test_files:
    try:
        tree = ast.parse(tp.read_text(errors="ignore"))
    except Exception:
        logger.debug("Failed to parse %s", tp, exc_info=True)
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    imported_test_modules[node.module].add(str(tp))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_test_modules[alias.name].add(str(tp))

# =============================================================================
# 3. Identify source modules imported in tests
# =============================================================================
tested_src = set()
for dotted in src_modules:
    mod = dotted
    # depth-first search for partial match
    while "." in mod:
        if mod in imported_test_modules:
            tested_src.add(src_modules[dotted])
            break
        mod = mod.rsplit(".", 1)[0]
    if dotted in imported_test_modules:
        tested_src.add(src_modules[dotted])

untested_src = [p for p in sorted(src_modules.values()) if p not in tested_src]

print("=== UNTESTED SOURCE MODULES (first 200) ===")
for p in untested_src[:200]:
    print(f"  {p.relative_to(ROOT)}")

print(f"\nTotal src: {len(src_modules)}")
print(f"Indirectly tested: {len(tested_src)}")
print(f"Untested: {len(untested_src)}")

# =============================================================================
# 4. Check for skip/xfail/hardcoded values in tests
# =============================================================================
print("\n=== SKIP/XFAIL IN TEST FILES ===")
for p in TESTS.rglob("test_*.py"):
    text = p.read_text(errors="ignore")
    if any(
        m in text
        for m in [
            "pytest.mark.skip",
            "pytest.mark.xfail",
            "skipTest",
            "unittest.skip",
            "@pytest.mark.skip",
            "@pytest.mark.xfail",
        ]
    ):
        print(f"  {p.relative_to(ROOT)}")

print("\n=== HARDCODED PASSWORDS/SECRETS IN TEST FILES (first 20) ===")
for p in TESTS.rglob("test_*.py"):
    text = p.read_text(errors="ignore")
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if (
            ("password" in line.lower() or "secret" in line.lower())
            and ("=" in line or ":" in line)
            and len(line) > 10
        ):
            print(f"  {p.relative_to(ROOT)}:{i}: {line.strip()[:120]}")
            break

# =============================================================================
# 5. Identify test categories (unit, integration, e2e) by path
# =============================================================================
print("\n=== TEST CATEGORIES ===")
for p in test_files:
    cat = (
        "unit"
        if "unit" in p.parts
        else "integration"
        if "integration" in p.parts
        else "e2e"
        if "e2e" in p.parts
        else "other"
    )
    print(f"  [{cat}] {p.relative_to(ROOT)}")
