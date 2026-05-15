import ast
from pathlib import Path

import pytest

FORBIDDEN_IMPORT_RULES: dict[str, set[str]] = {
    "core": {"pipeline"},
    "recon": {"dashboard"},
    "analysis": {"reporting"},
}


@pytest.mark.architecture
def test_forbidden_cross_layer_imports() -> None:
    workspace = Path(__file__).resolve().parents[2]
    src_root = workspace / "src"
    violations: list[str] = []

    for layer, forbidden_roots in FORBIDDEN_IMPORT_RULES.items():
        layer_dir = src_root / layer
        if not layer_dir.exists():
            continue

        for path in layer_dir.rglob("*.py"):
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(module):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module] if node.module else []
                else:
                    continue

                for imported in names:
                    if not imported:
                        continue
                    if imported.startswith("src."):
                        target_root = imported.split(".", 2)[1]
                    else:
                        target_root = imported.split(".", 1)[0]

                    if target_root in forbidden_roots:
                        relative_path = path.relative_to(workspace).as_posix()
                        violations.append(
                            f"{relative_path} imports forbidden layer '{target_root}' via '{imported}'"
                        )

    assert violations == [], "\n".join(violations)
