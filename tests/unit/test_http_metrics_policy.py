from __future__ import annotations

import importlib.util
from pathlib import Path

_POLICY = (
    Path(__file__).resolve().parents[1].parent
    / "src"
    / "dashboard"
    / "fastapi"
    / "http_metrics_policy.py"
)


def _load_policy():
    # Load the file directly: src.dashboard.__init__ eagerly imports FastAPI.
    spec = importlib.util.spec_from_file_location("http_metrics_policy", _POLICY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_http_metrics_are_opt_in() -> None:
    policy = _load_policy()
    assert policy.should_enable_http_metrics(None) is False
    assert policy.should_enable_http_metrics("") is False
    assert policy.should_enable_http_metrics("false") is False
    assert policy.should_enable_http_metrics("true") is True
    assert policy.should_enable_http_metrics(" ON ") is True


def test_http_metrics_path_normalization_bounds_cardinality() -> None:
    policy = _load_policy()
    assert policy.normalize_http_metrics_path("/api/jobs/123/logs") == "/api/jobs/{id}/logs"
    assert (
        policy.normalize_http_metrics_path("/api/findings/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        == "/api/findings/{uuid}"
    )
