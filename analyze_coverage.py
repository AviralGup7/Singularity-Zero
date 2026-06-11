from pathlib import Path

ROOT = Path(r"D:\cyber security test pipeline - Copy")
SRC = ROOT / "src"
TESTS = ROOT / "tests"

src_modules = {}
for p in SRC.rglob("*.py"):
    if p.name == "__init__.py":
        continue
    name = p.stem.replace(".", "_")
    src_modules[name] = p

test_files = []
for p in TESTS.rglob("*.py"):
    if p.name in ("__init__.py", "conftest.py"):
        continue
    test_files.append(p)

tested = set()
for p in test_files:
    name = p.stem.replace(".", "_")
    if name in src_modules:
        tested.add(src_modules[name])

untested = [p for p in sorted(src_modules.values()) if p not in tested]

print("=== UNTESTED SOURCE MODULES ===")
for p in untested:
    print(p)

print(f"\nTotal src modules: {len(src_modules)}")
print(f"Tested src modules: {len(tested)}")
print(f"Untested src modules: {len(untested)}")

# Also check for skip/xfail markers in test files
print("\n=== TEST FILES WITH SKIP/XFAIL MARKERS ===")
for p in test_files:
    text = p.read_text(errors="ignore")
    if (
        "pytest.mark.skip" in text
        or "pytest.mark.xfail" in text
        or "skipTest" in text
        or "unittest.skip" in text
    ):
        print(p)

# Check for hardcoded values in tests
print("\n=== TEST FILES WITH HARDCODED VALUES ===")
hardcoded = []
for p in test_files:
    text = p.read_text(errors="ignore")
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if (
            ("http://" in line or "https://" in line)
            and "example.com" not in line
            and "localhost" not in line
        ):
            hardcoded.append((str(p), i, line.strip()))
            break
        if "password" in line.lower() and ("=" in line or ":" in line):
            hardcoded.append((str(p), i, line.strip()))
            break
        if "secret" in line.lower() and "=" in line:
            hardcoded.append((str(p), i, line.strip()))
            break

for p, i, line in hardcoded[:20]:
    print(f"{p}:{i}: {line}")
