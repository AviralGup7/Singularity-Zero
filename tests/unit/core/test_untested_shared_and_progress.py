"""Coverage for shared URL normalizers, module registry, and progress constants."""

from __future__ import annotations

import pytest

from src.core.utils.shared import (
    GLOBAL_MODULE_REGISTRY,
    ModuleMeta,
    ModuleRegistry,
    get_module_meta,
    list_registered_modules,
    normalize_scope_entry,
    normalize_url,
    parse_plain_lines,
    register_module_meta,
)
from src.pipeline.constants.progress import _STAGE_BASELINE_PROGRESS, STAGE_BASELINE_PERCENT


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("*.example.com", "example.com"),
        ("example.com", "example.com"),
        ("*.api.example.com", "api.example.com"),
        ("*", "*"),
    ],
)
def test_normalize_scope_entry(raw: str, expected: str) -> None:
    assert normalize_scope_entry(raw) == expected


@pytest.mark.unit
def test_normalize_url_sorts_query_and_drops_default_ports() -> None:
    assert normalize_url("HTTPS://API.Example.com:443/V1/Users?b=2&a=1") == (
        "https://api.example.com/V1/Users?a=1&b=2"
    )
    assert normalize_url("http://example.com:80/path/") == "http://example.com/path/"
    assert normalize_url("   ") == ""
    assert normalize_url("example.com/x") == "https://example.com/x"


@pytest.mark.unit
def test_normalize_url_collapses_dot_segments() -> None:
    out = normalize_url("https://example.com/a/../b/./c")
    assert "/b/c" in out
    assert ".." not in out


@pytest.mark.unit
def test_parse_plain_lines_dedupes_and_skips_blank() -> None:
    text = "HTTPS://A.COM/X\nhttps://a.com/x\n\nHost.Example\n"
    values = parse_plain_lines(text)
    assert "https://a.com/X" in values or "https://a.com/x" in {v.lower() for v in values}
    assert "host.example" in values


@pytest.mark.unit
def test_module_registry_roundtrip() -> None:
    registry = ModuleRegistry()
    meta = ModuleMeta(name="demo", version="1.2.3", description="demo module", layer="core")
    registry.register(meta)
    assert registry.get("demo") is meta
    assert registry.get("missing") is None
    assert "demo" in registry.keys()
    assert registry.all()["demo"].version == "1.2.3"


@pytest.mark.unit
def test_register_module_meta_accepts_dict() -> None:
    name = "coverage_helper_module"
    register_module_meta({"name": name, "version": "0.0.1", "description": "tmp", "layer": "core"})
    found = get_module_meta(name)
    assert found is not None
    assert found.version == "0.0.1"
    names = [m.name for m in list_registered_modules()]
    assert name in names
    assert GLOBAL_MODULE_REGISTRY.get(name) is found


@pytest.mark.unit
def test_stage_baseline_percent_has_completed_and_aliases() -> None:
    assert STAGE_BASELINE_PERCENT["completed"] == 100
    assert "analysis" in STAGE_BASELINE_PERCENT
    assert "startup" not in _STAGE_BASELINE_PROGRESS
    assert "completed" not in _STAGE_BASELINE_PROGRESS
    assert all(isinstance(v, int) for v in STAGE_BASELINE_PERCENT.values())
