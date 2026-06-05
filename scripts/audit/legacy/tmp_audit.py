import ast
import logging
import re
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path(r"D:\cyber security test pipeline - Copy")
OUT = ROOT / "audit_report.txt"

issues = defaultdict(list)


def scan_comments(filepath, lines):
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        marker = re.search(r"\b(TODO|FIXME|HACK|BUG|XXX|WORKAROUND)\b", stripped, re.IGNORECASE)
        if marker:
            issues[(filepath, "todo_marker")].append(f"Line {i}: {stripped}")
        if re.search(r"(def |class |import |from |if |for |while )", stripped):
            issues[(filepath, "commented_code")].append(
                f"Line {i}: possible commented-out code: {stripped[:120]}"
            )


def check_docs_truthfulness(filepath, lines):
    content = "\n".join(lines)
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        doc = ast.get_docstring(node)
        if not doc:
            continue
        name = node.name
        lowered = doc.lower()
        name_l = name.lower()
        if "json" in lowered and "json" not in name_l:
            issues[(filepath, "misleading_doc")].append(
                f"Line {node.lineno}: '{name}' docstring mentions JSON but name does not"
            )
        if "xml" in lowered and "xml" not in name_l:
            issues[(filepath, "misleading_doc")].append(
                f"Line {node.lineno}: '{name}' docstring mentions XML but name does not"
            )
        if "deprecated" not in lowered and (
            "deprecated" in name_l or "legacy" in name_l or name_l.startswith("old_")
        ):
            issues[(filepath, "misleading_doc")].append(
                f"Line {node.lineno}: '{name}' docstring may be missing deprecation notice"
            )


for py_file in ROOT.rglob("*.py"):
    rel = str(py_file.relative_to(ROOT)).replace("\\", "/")
    if any(
        part
        in {".venv", ".venv-linux", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
        for part in py_file.relative_to(ROOT).parts
    ):
        continue
    try:
        text = py_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        logger.exception("Failed to read %s", py_file)
        continue
    lines = text.splitlines()
    if not lines:
        continue
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        issues[(rel, "syntax_error")].append("SyntaxError while parsing")
        continue

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if ast.get_docstring(node) is None:
                issues[(rel, "missing_class_docstring")].append(
                    f"Line {node.lineno}: class '{node.name}' missing docstring"
                )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
            if not name.startswith("_"):
                doc = ast.get_docstring(node)
                if doc is None or doc.strip() == "":
                    issues[(rel, "missing_func_docstring")].append(
                        f"Line {node.lineno}: function/method '{name}' missing docstring"
                    )
            if not name.startswith("_"):
                if node.returns is None:
                    issues[(rel, "missing_return_type")].append(
                        f"Line {node.lineno}: '{name}' missing return type annotation"
                    )
            actual_args = []
            if node.args.posonlyargs:
                actual_args.extend(node.args.posonlyargs)
            if node.args.args:
                actual_args.extend(node.args.args)
            if node.args.kwonlyargs:
                actual_args.extend(node.args.kwonlyargs)
            if node.args.vararg:
                actual_args.append(node.args.vararg)
            if node.args.kwarg:
                actual_args.append(node.args.kwarg)
            for a in actual_args:
                if a.arg in ("self", "cls"):
                    continue
                if a.annotation is None:
                    issues[(rel, "missing_arg_type")].append(
                        f"Line {node.lineno}: '{name}' arg '{a.arg}' missing type annotation"
                    )
            # Undocumented params heuristic
            doc = ast.get_docstring(node)
            if doc and not name.startswith("_"):
                param_mentions = set(
                    re.findall(r"[:\-]\s*param\s+(\w+)", doc, re.IGNORECASE)
                    + re.findall(r"`(\w+)`\s*[:\-]", doc)
                )
                for a in actual_args:
                    if a.arg in ("self", "cls"):
                        continue
                    if a.arg not in param_mentions:
                        issues[(rel, "undocumented_param")].append(
                            f"Line {node.lineno}: '{name}' arg '{a.arg}' not documented in docstring"
                        )
                has_return_doc = bool(
                    re.search(r"(returns?|return\s+type)\s*[:\-]", doc, re.IGNORECASE)
                )
                if not has_return_doc:
                    has_return_stmt = any(
                        isinstance(n, ast.Return) and n.value is not None for n in ast.walk(node)
                    )
                    if has_return_stmt:
                        issues[(rel, "undocumented_return")].append(
                            f"Line {node.lineno}: '{name}' returns value but docstring lacks return section"
                        )
    scan_comments(rel, lines)
    check_docs_truthfulness(rel, lines)

# Group output
categories = defaultdict(list)
for (rel, cat), msgs in issues.items():
    categories[cat].extend(msgs)

with OUT.open("w", encoding="utf-8") as out:
    out.write("=== Documentation / Type / Docstring Audit ===\n\n")
    for cat in sorted(categories):
        msgs = categories[cat]
        out.write(f"--- {cat.upper()} ({len(msgs)} occurrences) ---\n")
        for m in msgs[:200]:
            out.write(f"  {m}\n")
        if len(msgs) > 200:
            out.write(f"  ... and {len(msgs) - 200} more\n")
        out.write("\n")

    for fname in ("CHANGES.md", "CHANGELOG.md", "CHANGELOG"):
        p = ROOT / fname
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="ignore")
            nonempty = [line for line in text.splitlines() if line.strip()]
            out.write(
                f"Found {fname}. Latest non-empty line: {nonempty[-1] if nonempty else '(empty)'}\n"
            )
            break
    else:
        out.write("No CHANGES.md / CHANGELOG.md found.\n")

print(f"Wrote report to {OUT}")
