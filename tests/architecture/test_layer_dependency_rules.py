import ast
import unittest
from pathlib import Path

LAYER_ORDER = {
    "core": 0,
    "recon": 1,
    "analysis": 2,
    "detection": 2,
    "intelligence": 2,
    "decision": 2,
    "execution": 1,
    "reporting": 4,
    "platform": 1,
    "ui": 4,
    "plugins": 2,
}

ALLOWED_LAYER_DEPENDENCIES: dict[str, set[str]] = {
    "core": {"core"},
    "recon": {"core", "recon", "platform"},
    "analysis": {
        "core",
        "recon",
        "analysis",
        "detection",
        "plugins",
        "platform",
        "decision",
        "execution",
    },
    "detection": {"core", "recon", "analysis", "detection", "plugins"},
    "intelligence": {"core", "recon", "analysis", "intelligence", "plugins"},
    "decision": {"core", "analysis", "decision"},
    "execution": {"core", "recon", "analysis", "decision", "execution", "platform"},
    "reporting": {
        "core",
        "recon",
        "analysis",
        "intelligence",
        "decision",
        "execution",
        "reporting",
        "plugins",
        "platform",
    },
    "platform": {"core", "platform"},
    "ui": {"core", "reporting", "platform", "ui"},
    "plugins": {"core", "analysis", "plugins"},
}

COMPOSITION_ROOT_OVERRIDES: dict[str, set[str]] = {
    "platform/services/pipeline_orchestrator.py": {
        "recon",
        "analysis",
        "intelligence",
        "decision",
        "execution",
        "reporting",
    },
    "platform/runtime.py": {
        "recon",
        "analysis",
        "intelligence",
        "decision",
        "execution",
        "reporting",
    },
    "platform/maintenance.py": {"reporting"},
    "recon/ranking_support.py": {"analysis"},
    "recon/scoring.py": {"analysis"},
    "recon/urls.py": {"analysis"},
    "core/mutation_engine.py": {"analysis"},
    "analysis/intelligence_findings.py": {"intelligence"},
}

ALLOWED_EXTERNAL_PREFIXES = {
    "typing",
    "dataclasses",
    "pathlib",
    "urllib",
    "json",
    "enum",
    "dashboard_app",
    "api_tests",
}


class LayerDependencyRuleTests(unittest.TestCase):
    def test_no_upward_layer_imports(self) -> None:
        violations: list[str] = []
        workspace = Path(__file__).resolve().parents[2]
        for layer in LAYER_ORDER:
            layer_dir = workspace / layer
            if not layer_dir.exists():
                continue
            for path in layer_dir.rglob("*.py"):
                if path.name == "__pycache__":
                    continue
                module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(module):
                    if not isinstance(node, (ast.Import, ast.ImportFrom)):
                        continue
                    names: list[str] = []
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names = [node.module]
                    for imported in names:
                        root = imported.split(".", 1)[0]
                        if root in ALLOWED_EXTERNAL_PREFIXES:
                            continue
                        if root not in LAYER_ORDER:
                            continue
                        relative_path = str(path.relative_to(workspace)).replace("\\", "/")
                        allowed_layers = set(ALLOWED_LAYER_DEPENDENCIES.get(layer, {layer}))
                        allowed_layers.update(COMPOSITION_ROOT_OVERRIDES.get(relative_path, set()))
                        if root not in allowed_layers:
                            violations.append(
                                f"{relative_path} imports disallowed layer '{root}' via '{imported}'"
                            )
        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
