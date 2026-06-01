PLUGIN_MANIFEST = {
    "id": "xxe.unsafe_xml_parser",
    "name": "Unsafe XML Parser Configuration",
    "version": "1.0.0",
    "kind": "validator",
    "description": (
        "Detect source snippets that enable DTDs, external entities, or unsafe XML parser defaults."
    ),
    "group": "xxe",
    "entrypoint": "run",
    "sandbox": "process",
    "enabled_by_default": True,
    "capabilities": ["static-source", "xxe"],
    "tags": ["xxe", "cwe-611", "xml"],
    "timeout_seconds": 10,
}

import re  # noqa: E402 - manifest must stay static and easy for the plugin loader to extract.

_PATTERNS = (
    (
        "python_lxml_resolve_entities",
        re.compile(r"XMLParser\s*\([^)]*resolve_entities\s*=\s*True", re.IGNORECASE),
        "high",
        "lxml XMLParser resolves entities.",
    ),
    (
        "python_lxml_load_dtd",
        re.compile(r"XMLParser\s*\([^)]*load_dtd\s*=\s*True", re.IGNORECASE),
        "medium",
        "lxml XMLParser loads DTDs.",
    ),
    (
        "java_document_builder_factory",
        re.compile(r"DocumentBuilderFactory\s*\.\s*newInstance\s*\(", re.IGNORECASE),
        "medium",
        "DocumentBuilderFactory is used without visible XXE hardening.",
    ),
    (
        "java_sax_parser_factory",
        re.compile(r"SAXParserFactory\s*\.\s*newInstance\s*\(", re.IGNORECASE),
        "medium",
        "SAXParserFactory is used without visible XXE hardening.",
    ),
    (
        "java_xml_input_factory",
        re.compile(r"XMLInputFactory\s*\.\s*newInstance\s*\(", re.IGNORECASE),
        "medium",
        "XMLInputFactory is used without visible DTD/entity hardening.",
    ),
    (
        "dotnet_dtd_parse",
        re.compile(r"DtdProcessing\s*=\s*DtdProcessing\s*\.\s*Parse", re.IGNORECASE),
        "high",
        "XmlReaderSettings permits DTD processing.",
    ),
    (
        "php_disable_entity_loader_false",
        re.compile(r"libxml_disable_entity_loader\s*\(\s*false\s*\)", re.IGNORECASE),
        "high",
        "libxml external entity loading is explicitly enabled.",
    ),
)

_HARDENING_MARKERS = (
    "disallow-doctype-decl",
    "external-general-entities",
    "external-parameter-entities",
    "nonvalidating/load-external-dtd",
    "setexpandentityreferences(false)",
    "support_dtd",
    "issupportingexternalentities",
    "dtdprocessing.prohibit",
    "dtdprocessing.ignore",
    "defusedxml",
    "no_network=true",
    "resolve_entities=false",
)


from collections.abc import Generator
from typing import Any


def _source_items(payload: dict[str, Any]) -> Generator[dict[str, str]]:
    files = payload.get("files", [])
    if isinstance(files, list) and files:
        for index, item in enumerate(files):
            if not isinstance(item, dict):
                continue
            yield {
                "path": str(item.get("path") or f"inline_{index}"),
                "content": str(item.get("content") or item.get("source") or ""),
            }
        return

    yield {
        "path": str(payload.get("path") or "inline"),
        "content": str(
            payload.get("content") or payload.get("source") or payload.get("code") or ""
        ),
    }


def _line_number(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


def _has_hardening(content: str) -> bool:
    compact = content.lower().replace(" ", "")
    lowered = content.lower()
    return any(marker in compact or marker in lowered for marker in _HARDENING_MARKERS)


def run(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return findings

    for item in _source_items(payload):
        content = item["content"]
        if not content:
            continue
        hardened = _has_hardening(content)
        for signal, pattern, severity, message in _PATTERNS:
            for match in pattern.finditer(content):
                if hardened and signal in (
                    "java_document_builder_factory",
                    "java_sax_parser_factory",
                    "java_xml_input_factory",
                ):
                    continue
                findings.append(
                    {
                        "title": "Unsafe XML parser configuration",
                        "category": "xxe",
                        "cwe": "CWE-611",
                        "severity": severity,
                        "confidence": 0.86 if severity == "high" else 0.72,
                        "path": item["path"],
                        "line": _line_number(content, match.start()),
                        "signals": [signal],
                        "evidence": {"message": message},
                    }
                )

    return findings[:50]
