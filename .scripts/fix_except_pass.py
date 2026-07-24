"""Batch-fix silent except Exception: pass blocks across the src/ tree."""
import os
import re
import sys

SRC = r"D:\cyber security test pipeline - Copy\src"

# Files where silent except is intentional (cleanup/disposal patterns)
INTENTIONAL_SILENCE = {
    r"dashboard\fastapi\lifespan.py",      # cleanup on shutdown
    r"core\utils\shared_sessions.py",       # cleanup
}

def fix_file(filepath: str) -> bool:
    """Fix except Exception: pass blocks. Returns True if changes made."""
    rel = os.path.relpath(filepath, SRC)
    with open(filepath, encoding="utf-8", errors="replace") as f:
        content = f.read()

    original = content
    basename = os.path.basename(filepath)

    if "except Exception:" not in content:
        return False

    # Check if file has a logger
    has_logger = bool(re.search(r"logger\s*=\s*logging\.getLogger", content))

    # ---- Add logger if missing and we have fixable patterns ----
    if not has_logger:
        # Check if there's a fixable pattern
        if not re.search(r"except Exception:\s*\n\s+pass", content):
            return False
        # Add import logging if needed
        if "import logging" not in content:
            content = "import logging\n" + content
        # Add logger definition after imports
        lines = content.split("\n")
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("import ") or line.startswith("from "):
                insert_idx = i + 1
        # Find a blank line after imports
        while insert_idx < len(lines) and lines[insert_idx].strip() == "":
            insert_idx += 1
            break
        lines.insert(insert_idx, 'logger = logging.getLogger(__name__)')
        lines.insert(insert_idx + 1, "")
        content = "\n".join(lines)
        has_logger = True

    if not has_logger:
        return False

    # ---- Replace except Exception:\n            pass ----
    # Match: optional # noqa, then newline, then whitespace+pass
    pattern = re.compile(
        r"(^[ \t]*)(except\s+(?:\w+(?:\s+as\s+\w+)?|[A-Za-z_]\w*)\s*:\s*(?:#.*?)?\n)"
        r"([ \t]*)pass\s*(?:#.*?)?$",
        re.MULTILINE,
    )

    def replacer(m: re.Match) -> str:
        indent1 = m.group(1)
        except_line = m.group(2)
        indent2 = m.group(3)
        msg = f"Operation failed in {basename}"
        return f"{indent1}{except_line}{indent2}logger.warning(\"{msg}\", exc_info=True)"

    new_content, count = pattern.subn(replacer, content)

    if new_content == original and count == 0:
        return False

    # Validate syntax
    try:
        compile(new_content, filepath, "exec")
    except SyntaxError as e:
        print(f"  SYNTAX ERROR in {rel}: {e}", file=sys.stderr)
        return False

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"  {rel} ({count} fixes)")
    return True


def main():
    fixed = 0
    errors = 0
    for root, dirs, files in sorted(os.walk(SRC)):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            rel = os.path.relpath(path, SRC)
            if rel in INTENTIONAL_SILENCE:
                continue
            try:
                if fix_file(path):
                    fixed += 1
            except Exception as e:
                print(f"  ERROR {rel}: {e}", file=sys.stderr)
                errors += 1

    print(f"\nDone: {fixed} files fixed, {errors} errors")


if __name__ == "__main__":
    main()
