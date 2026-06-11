from pathlib import Path

ROOT = Path("src").resolve()

# Find all directories under src that contain at least one .py file but no __init__.py
missing_inits = []
for d in sorted(ROOT.rglob("*")):
    if d.is_dir():
        py_files = list(d.glob("*.py"))
        if py_files and not (d / "__init__.py").exists() and d != ROOT:
            missing_inits.append(
                (str(d.relative_to(ROOT)), [str(p.relative_to(ROOT)) for p in py_files[:3]])
            )

print("Directories with Python files but missing __init__.py (may be namespace packages):\n")
for d, samples in missing_inits:
    print(f"{d}/  (sample files: {', '.join(samples)})")
print(f"\n[Count] {len(missing_inits)} directories.")
