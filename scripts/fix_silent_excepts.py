"""Fix silent exception swallowing: replace `except Exception: pass` with logging."""

import re
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"


def has_logger(content: str) -> bool:
    return bool(
        re.search(r"^\s*(import logging|logger\s*=\s*logging\.getLogger)", content, re.MULTILINE)
    )


def add_logger(content: str) -> str:
    lines = content.split("\n")
    insertion_line = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("from __future__"):
            continue
        if stripped.startswith(("import ", "from ")):
            insertion_line = i + 1
        if stripped.startswith(('"""', "'''", "#") or stripped == ""):
            continue
        if insertion_line > 0:
            break
    # find last import line
    last_import = 0
    for i, line in enumerate(lines):
        if line.strip().startswith(("import ", "from ")):
            last_import = i
    insertion_line = last_import + 1 if last_import > 0 else 0

    indent = ""
    lines.insert(insertion_line, f"{indent}import logging")
    lines.insert(insertion_line + 1, f"{indent}logger = logging.getLogger(__name__)")
    lines.insert(insertion_line + 2, "")
    return "\n".join(lines)


def _classify_context(content: str, pos: int) -> str:
    pre_lines = content[:pos].split("\n")
    context = " ".join(pre_lines[-8:]).lower()
    if any(
        w in context
        for w in [
            "close",
            "cleanup",
            "shutdown",
            "__del__",
            "destructor",
            "release",
            "detach",
            "finaliz",
        ]
    ):
        return "cleanup"
    if any(w in context for w in ["metric", "counter", "gauge", "observ"]):
        return "metric"
    if any(w in context for w in ["probe", "acl", "bucket", "cloud"]):
        return "probe"
    return "general"


def fix_file(filepath: Path) -> bool:
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    original = content
    has_log = has_logger(content)

    LOG_CALLS = {
        "cleanup": 'logger.debug("Non-critical cleanup error", exc_info=True)',
        "metric": 'logger.debug("Metrics tracking error", exc_info=True)',
        "probe": 'logger.warning("Security probe error", exc_info=True)',
        "general": 'logger.warning("Suppressed exception", exc_info=True)',
    }

    def replace_pass(m):
        indent = m.group(2)
        ctx = _classify_context(content, m.start())
        exc_line = m.group(1).rstrip()
        return f"{exc_line}\n{indent}    {LOG_CALLS[ctx]}"

    # Pattern: full except line + newline + indented pass
    pattern = re.compile(
        r"((?:except\s+(?:Exception|BaseException)\s*:?)\s*(?:#\s*[^\n]*)?)\n([ \t]+)pass",
        re.MULTILINE,
    )
    content = pattern.sub(replace_pass, content)

    if content == original:
        return False

    if not has_log and "logger." in content:
        content = add_logger(content)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return True


def main():
    fixed = 0
    for py_file in sorted(SRC_DIR.rglob("*.py")):
        if fix_file(py_file):
            print(f"Fixed: {py_file.relative_to(SRC_DIR.parent)}")
            fixed += 1
    print(f"\nFixed {fixed} files.")


if __name__ == "__main__":
    main()
