import ast
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path(r"D:\cyber security test pipeline - Copy")
DEPRECATED = {
    "distutils",
    "imp",
    "optparse",
    "commands",
    "md5",
    "sha",
    "cStringIO",
    "asyncore",
    "asynchat",
    "sunau",
    "xdrlib",
    "sunaudiodev",
}
findings = []


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


def add(path, lineno, category, detail):
    findings.append(
        {
            "path": rel(path),
            "line": lineno,
            "category": category,
            "detail": detail,
        }
    )


SKIP = {".venv", "venv", "node_modules", "__pycache__", ".git"}
pyfiles = [p for p in ROOT.rglob("*.py") if not any(s in p.parts for s in SKIP)]

for py in pyfiles:
    try:
        src = py.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src)
    except Exception:
        logger.exception("Failed to read/parse %s", py)
        continue

    imported_names = {}  # bind -> (lineno, module_or_name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bind = alias.asname or alias.name.split(".")[0]
                imported_names[bind] = (node.lineno, alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    add(
                        py,
                        node.lineno,
                        "wildcard_import",
                        f"from {module or '(relative)'} import * (PEP8 / tooling / namespace risk)",
                    )
                    if module:
                        imported_names[module.split(".")[0]] = (node.lineno, module)
                else:
                    bind = alias.asname or alias.name
                    imported_names[bind] = (node.lineno, module)
            if node.level and node.level > 1:
                add(
                    py,
                    node.lineno,
                    "relative_import_too_deep",
                    f"relative import level {node.level} for '{module}' (possible wrong path)",
                )

    for bind, (ln, mod) in list(imported_names.items()):
        base = (mod or bind).split(".")[0]
        if base in DEPRECATED or mod in DEPRECATED:
            add(py, ln, "deprecated_import", f"deprecated module '{mod or bind}' imported")

    assigns = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assigns.append((t.id, node.lineno))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigns.append((node.target.id, node.lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args:
                assigns.append((arg.arg, node.lineno))
        elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            assigns.append((node.target.id, node.lineno))
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    assigns.append((item.optional_vars.id, node.lineno))

    seen_a = set()
    for a_name, a_line in assigns:
        if (a_name, a_line) in seen_a:
            continue
        seen_a.add((a_name, a_line))
        for name, (imp_line, _) in imported_names.items():
            if a_name == name and a_line > imp_line + 1:
                add(
                    py,
                    a_line,
                    "shadowed_name",
                    f"name '{name}' (imported at line {imp_line}) shadowed by assignment at line {a_line}",
                )
                break

    skip = {"os", "sys", "re", "io", "typing"}
    for bind, (ln, mod) in list(imported_names.items()):
        if bind in skip:
            continue
        if bind not in src:
            add(
                py,
                ln,
                "unused_import_heuristic",
                f"imported name '{bind}' (from '{mod or bind}') not obviously used",
            )

    sf = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                sf.setdefault((module, alias.name), []).append(node.lineno)
    for (mod, name), lines in sf.items():
        if len(lines) > 1:
            add(
                py,
                lines[-1],
                "duplicate_import",
                f"'{name}' from '{mod}' imported multiple times at lines {lines}",
            )

for py in pyfiles:
    try:
        src = py.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src)
    except Exception:
        logger.exception("Failed to read/parse %s", py)
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            current = ROOT
            for part in module.split("."):
                current = current / part
                if current.is_dir():
                    if not (current / "__init__.py").exists():
                        add(
                            py,
                            node.lineno,
                            "missing_init_py",
                            f"package directory '{rel(current)}' imported but missing __init__.py",
                        )
                        break
                else:
                    break

out = Path(r"D:\cyber security test pipeline - Copy\import_analysis_report.txt")
lines = [f"Total modules analyzed: {len(pyfiles)}"]
lines.append(f"Total findings: {len(findings)}\n")
from collections import Counter

cats = Counter(f["category"] for f in findings)
for cat, cnt in cats.items():
    lines.append(f"  {cat}: {cnt}")
lines.append("\n--- Detailed findings ---")
seen = set()
for f in sorted(findings, key=lambda x: (x["path"], x["line"])):
    key = (f["path"], f["line"], f["category"], f["detail"])
    if key in seen:
        continue
    seen.add(key)
    lines.append(f"{f['path']}:{f['line']}: [{f['category']}] {f['detail']}")

Path(out).write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines[:100]))
print(f"\nReport written to {out}{' ' * 80}")
