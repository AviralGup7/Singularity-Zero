from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load(rel: str, name: str):
    path = REPO / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_auth_flow_engine_is_an_operator_choice() -> None:
    select = _load("src/execution/auth/select.py", "auth_select")
    assert select.normalize_auth_flow_engine(None) == "builtin"
    assert select.normalize_auth_flow_engine("YAML") == "yaml"
    assert select.normalize_auth_flow_engine("builtin") == "builtin"


def test_optional_probe_catalog_keys_are_opt_in() -> None:
    text = (REPO / "src/analysis/plugins/active.py").read_text(encoding="utf-8")
    for key in (
        "secrets_response_scanner",
        "csp_bypass_probe",
        "api_security_assessor",
        "graphql_batch_attack_probe",
        "differential_logic_prober",
    ):
        assert key in text
    assert text.count("enabled_by_default=False") >= 6


def test_optional_probe_bindings_point_at_adapters() -> None:
    text = (REPO / "src/analysis/plugin_runtime/definitions.py").read_text(encoding="utf-8")
    assert "src.analysis.optional_probes" in text
    assert "secrets_response_scanner" in text


def test_cockpit_edges_route_exists() -> None:
    text = (REPO / "src/dashboard/fastapi/routers/cockpit/edges.py").read_text(encoding="utf-8")
    assert '"/edges"' in text
    assert "get_cockpit_edges" in text
    nodes = (REPO / "src/dashboard/fastapi/routers/cockpit/nodes.py").read_text(encoding="utf-8")
    assert "from src.dashboard.fastapi.routers.cockpit.edges import" in nodes
    assert "def _build_run_artifact_graph" not in nodes
