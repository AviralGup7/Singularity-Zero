"""AST-aware detection facade.

Aggregates the JavaScript sink/source analyzer, the WebAssembly
introspector, and the prototype pollution walker behind a single
``analyze`` entry point. The detection runtime uses this facade when
AST-aware plugins are enabled.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from src.detection.ast.js_sink_analyzer import analyze_html as _analyze_js
from src.detection.ast.js_sink_analyzer import analyze_scripts as _analyze_scripts
from src.detection.ast.js_sink_analyzer import (
    extract_next_data,
    extract_source_map_url,
    fetch_inline_scripts,
)
from src.detection.ast.prototype_pollution_walker import (
    analyze_json_string,
)
from src.detection.ast.prototype_pollution_walker import (
    walk_html as _walk_pollution,
)
from src.detection.ast.wasm_introspector import batch_introspect as _batch_wasm
from src.detection.ast.wasm_introspector import is_wasm_bytes, is_wasm_url

logger = logging.getLogger(__name__)


def analyze_html_for_sinks(
    html: str,
    *,
    url: str,
    script_texts: Iterable[tuple[str, str, int]] | None = None,
) -> list[dict[str, Any]]:
    """Return a list of detection findings from an HTML document."""

    findings: list[dict[str, Any]] = []
    for finding in _analyze_js(html, url=url):
        findings.append(
            {
                "url": finding.url,
                "indicator": "js_sink_source",
                "summary": f"{finding.pattern_type} {finding.pattern} @ line {finding.line}",
                "severity": finding.severity,
                "confidence": 0.55 if finding.severity in {"medium", "high"} else 0.40,
                "line": finding.line,
                "pattern_type": finding.pattern_type,
                "pattern": finding.pattern,
                "has_sanitizer": finding.has_sanitizer,
                "sanitizer_name": finding.sanitizer_name,
                "source_map": finding.source_map,
                "context": finding.context,
                "source_name": finding.source_name,
            }
        )
    if script_texts:
        for finding in _analyze_scripts(script_texts):
            findings.append(
                {
                    "url": finding.url,
                    "indicator": "js_sink_source",
                    "summary": f"{finding.pattern_type} {finding.pattern} @ line {finding.line}",
                    "severity": finding.severity,
                    "confidence": 0.55 if finding.severity in {"medium", "high"} else 0.40,
                    "line": finding.line,
                    "pattern_type": finding.pattern_type,
                    "pattern": finding.pattern,
                    "has_sanitizer": finding.has_sanitizer,
                    "sanitizer_name": finding.sanitizer_name,
                    "source_map": finding.source_map,
                    "context": finding.context,
                }
            )
    return findings


def analyze_html_for_prototype_pollution(html: str, *, url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in _walk_pollution(html, url=url):
        findings.append(
            {
                "url": finding.url,
                "indicator": "prototype_pollution_candidate",
                "summary": finding.pattern,
                "severity": finding.severity,
                "confidence": 0.60 if finding.severity == "high" else 0.45,
                "line": finding.line,
                "pattern_type": finding.pattern_type,
                "pattern": finding.pattern,
                "target": finding.target,
                "key": finding.key,
                "value": finding.value,
                "context": finding.context,
            }
        )
    return findings


def analyze_object_for_prototype_pollution(obj: Any, *, url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in analyze_json_string(json_dumps_if_needed(obj), url=url):
        findings.append(
            {
                "url": finding.url,
                "indicator": "prototype_pollution_data_shape",
                "summary": finding.pattern,
                "severity": finding.severity,
                "confidence": 0.55 if finding.severity == "high" else 0.40,
                "pattern_type": finding.pattern_type,
                "pattern": finding.pattern,
                "target": finding.target,
                "key": finding.key,
            }
        )
    return findings


def analyze_wasm_candidates(
    candidates: Iterable[tuple[str, bytes | None]],
) -> list[dict[str, Any]]:
    return _batch_wasm(candidates)


def analyze_response(
    *,
    url: str,
    body: bytes | str | None,
    content_type: str | None,
) -> list[dict[str, Any]]:
    """Dispatch a single response through the AST detectors.

    Returns an empty list when the response is not analyzable.
    """

    if body is None:
        return []
    findings: list[dict[str, Any]] = []
    if isinstance(body, bytes):
        if is_wasm_bytes(body):
            for finding in _batch_wasm([(url, body)]):
                findings.append(
                    {
                        **finding,
                        "indicator": finding.get("indicator", "wasm_finding"),
                        "url": url,
                    }
                )
            return findings
        try:
            decoded = body.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - defensive
            return []
    else:
        decoded = body

    ct = (content_type or "").lower()
    if "html" in ct or "<html" in decoded.lower() or "<script" in decoded.lower():
        findings.extend(analyze_html_for_sinks(decoded, url=url))
        findings.extend(analyze_html_for_prototype_pollution(decoded, url=url))
    elif "json" in ct or decoded.lstrip().startswith(("{", "[")):
        findings.extend(analyze_object_for_prototype_pollution(decoded, url=url))
    return findings


def json_dumps_if_needed(value: Any) -> str:
    import json as _json

    if isinstance(value, str):
        return value
    try:
        return _json.dumps(value)
    except (TypeError, ValueError):
        return ""


__all__ = [
    "analyze_html_for_sinks",
    "analyze_html_for_prototype_pollution",
    "analyze_object_for_prototype_pollution",
    "analyze_wasm_candidates",
    "analyze_response",
    "extract_next_data",
    "extract_source_map_url",
    "fetch_inline_scripts",
    "is_wasm_bytes",
    "is_wasm_url",
]
