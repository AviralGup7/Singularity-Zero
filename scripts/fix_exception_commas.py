import re
from pathlib import Path


def fix_file(path: Path):
    content = path.read_text(encoding="utf-8")

    lines = content.splitlines()
    modified = False
    for i, line in enumerate(lines):
        match = re.search(
            r"^(\s*)except\s+([a-zA-Z0-9_\.]+)(?:\s*,\s*[a-zA-Z0-9_\.]+)+\s*:",
            line,
        )
        if match:
            indent = match.group(1)
            stripped = line.strip().removeprefix("except").removesuffix(":").strip()
            parts = [e.strip() for e in stripped.split(",")]
            var_name = parts.pop()
            if len(parts) == 1:
                lines[i] = f"{indent}except {parts[0]} as {var_name}:"
            else:
                lines[i] = f"{indent}except ({', '.join(parts)}) as {var_name}:"
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
