from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.plugins.loader import DynamicPluginCatalog
from src.core.plugins.sandbox import ProcessSandboxCallable

REPO_ROOT = Path(__file__).resolve().parents[3]


def _runtime_imports():
    try:
        from src.analysis.plugin_runtime import ANALYZER_BINDINGS, prime_analysis_primitives
        from src.analysis.plugin_runtime._runner import run_registered_analyzer
    except (IndentationError, SyntaxError) as exc:
        filename = str(getattr(exc, "filename", "") or "")
        is_runtime_file = (
            "src\\analysis\\plugin_runtime" in filename or "src/analysis/plugin_runtime" in filename
        )
        if not is_runtime_file:
            pytest.skip(f"plugin runtime import is blocked by unrelated syntax error in {filename}")
        raise
    return ANALYZER_BINDINGS, prime_analysis_primitives, run_registered_analyzer


class _XXEResponseCache:
    def request(self, url: str, **kwargs: object) -> dict[str, object]:
        headers = kwargs.get("headers")
        normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        if normalized.get("x-xxe-probe") == "1":
            return {
                "url": url,
                "status_code": 200,
                "body_text": "root:x:0:0:root:/root:/bin/bash",
            }
        return {"url": url, "status_code": 200, "body_text": ""}


class _XMLBombResponseCache:
    def request(self, url: str, **kwargs: object) -> dict[str, object]:
        headers = kwargs.get("headers")
        normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        payload_name = normalized.get("x-xml-bomb-probe", "")
        if not payload_name:
            return {
                "url": url,
                "status_code": 200,
                "headers": {"Content-Type": "application/xml"},
                "body_text": "<root>ready</root>",
                "elapsed": 0,
            }
        if payload_name == "xxe_file_read":
            return {
                "url": url,
                "status_code": 200,
                "headers": {"Content-Type": "application/xml"},
                "body_text": "root:x:0:0:root:/root:/bin/bash",
                "elapsed": 0.1,
            }
        return {
            "url": url,
            "status_code": 200,
            "headers": {"Content-Type": "application/xml"},
            "body_text": "<root>ok</root>",
            "elapsed": 0.1,
        }


def test_xxe_active_probe_binding_executes_runner_and_finds_file_read() -> None:
    ANALYZER_BINDINGS, prime_analysis_primitives, run_registered_analyzer = _runtime_imports()

    binding = ANALYZER_BINDINGS["xxe_active_probe"]
    ctx = prime_analysis_primitives(
        urls=set(),
        responses=[],
        priority_urls=["https://api.example.test/xml/import"],
        response_cache=_XXEResponseCache(),
    )

    findings = run_registered_analyzer(binding, ctx, analyzer_key="xxe_active_probe")

    assert findings
    assert findings[0]["url"] == "https://api.example.test/xml/import"
    assert "xxe_file_read" in findings[0]["issues"]


def test_xml_bomb_detector_binding_executes_runner_and_finds_xxe() -> None:
    ANALYZER_BINDINGS, prime_analysis_primitives, run_registered_analyzer = _runtime_imports()

    binding = ANALYZER_BINDINGS["xml_bomb_detector"]
    ctx = prime_analysis_primitives(
        urls=set(),
        responses=[],
        priority_urls=["https://api.example.test/xml/import"],
        response_cache=_XMLBombResponseCache(),
    )

    findings = run_registered_analyzer(binding, ctx, analyzer_key="xml_bomb_detector")

    assert findings
    assert findings[0]["category"] == "xml_bomb_xxe"
    assert "xxe_file_read_confirmed" in findings[0]["signals"]


def test_xxe_unsafe_xml_parser_dynamic_plugin_is_discovered_and_sandbox_safe(
    tmp_path: Path,
) -> None:
    plugin_path = REPO_ROOT / "src" / "core" / "frontier" / "plugins" / "xxe_unsafe_xml_parser.py"
    fixture_path = REPO_ROOT / "tests" / "fixtures" / "security_patterns" / "xxe_unsafe_parser.json"
    isolated_plugin = tmp_path / plugin_path.name
    isolated_plugin.write_text(plugin_path.read_text(encoding="utf-8"), encoding="utf-8")
    catalog = DynamicPluginCatalog((tmp_path,))

    records = catalog.refresh()
    record = next(item for item in records if item.manifest.id == "xxe.unsafe_xml_parser")
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    findings = ProcessSandboxCallable(record.manifest, record.path)(payload)

    assert record.manifest.kind == "validator"
    assert record.manifest.sandbox == "process"
    assert {finding["path"] for finding in findings} == {
        "src/main/java/example/XmlController.java",
        "app/parsers/xml_loader.py",
    }
    assert {finding["category"] for finding in findings} == {"xxe"}
