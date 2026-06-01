import re
from pathlib import Path


def fix_file(path: Path):
    content = path.read_text(encoding="utf-8")


    # We want to keep track of the leading indentation of the match
    # So let's write a line-by-line replacement instead, which is safer
    lines = content.splitlines()
    modified = False
    for i, line in enumerate(lines):
        # match line
        match = re.search(r"^(\s*)except\s+([a-zA-Z0-9_\.]+)(?:\s*,\s*[a-zA-Z0-9_\.]+)+\s*:", line)
        if match:
            indent = match.group(1)
            # strip leading/trailing spaces and colon
            stripped = line.strip().removeprefix("except").removesuffix(":").strip()
            exceptions = [e.strip() for e in stripped.split(",")]
            joined = ", ".join(exceptions)
            lines[i] = f"{indent}except ({joined}):"
            modified = True

    if modified:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Fixed exception syntax in {path}")

def main():
    root = Path("src")
    for p in root.rglob("*.py"):
        fix_file(p)
    tests_root = Path("tests")
    if tests_root.exists():
        for p in tests_root.rglob("*.py"):
            fix_file(p)

if __name__ == "__main__":
    main()
