"""Prototype pollution AST walker.

Performs a regex-driven AST walk over JavaScript / TypeScript / Vue SFC
fragments to identify prototype pollution sinks. The walker intentionally
operates on a stream-of-text view (no esprima dependency) and returns
typed findings so the exploitation layer can promote the result into a
safe ``__proto__`` probe.

The walker is also exposed as ``analyze_object`` for static data-shape
analysis (e.g. JSON merge utilities serialized into a web bundle).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.detection.ast.js_sink_analyzer import (
    _PROTO_RE,
    _truncate_context,
)

logger = logging.getLogger(__name__)


_PROTO_TRAVERSAL_RE = re.compile(
    r"""
    (?:^|[\s\(\{])
    (?P<target>[A-Za-z_$][\w$.]*)
    \[
    (?P<key>
        ['"]?(?:__proto__|constructor|prototype)['"]?
    )
    \]
    \s*=\s*
    (?P<value>[^;\n]+)
    """,
    re.VERBOSE | re.IGNORECASE,
)

_JSON_MERGE_FUNCS = re.compile(
    r"\b(?P<fn>extend|merge|deepMerge|mergeDeep|defaultsDeep|setWith|setIn|assign)\s*\(",
    re.IGNORECASE,
)

# Pattern for property access like: target.__proto__ = value
_PROTO_ASSIGN_RE = re.compile(
    r"""
    (?P<target>[A-Za-z_$][\w$.]*)
    \.
    (?P<key>__proto__|constructor|prototype)
    \s*=\s*
    (?P<value>[^;\n]+)
    """,
    re.VERBOSE | re.IGNORECASE,
)


@dataclass(slots=True)
class PrototypePollutionFinding:
    url: str
    line: int
    pattern: str
    pattern_type: str  # traversal | assign | merge | forin
    severity: str
    context: str
    target: str | None = None
    key: str | None = None
    value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        body = {
            "url": self.url,
            "line": self.line,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "context": self.context,
            "target": self.target,
            "key": self.key,
            "value": self.value,
        }
        body.update(self.metadata)
        return body


# ---------------------------------------------------------------------------
# Source walking
# ---------------------------------------------------------------------------


def _iter_lines_with_offset(code: str, line_offset: int) -> Iterable[tuple[int, str]]:
    for index, line in enumerate(code.splitlines(), start=1):
        yield line_offset + index - 1, line


def walk_script(
    code: str,
    *,
    url: str,
    line_offset: int = 1,
) -> list[PrototypePollutionFinding]:
    findings: list[PrototypePollutionFinding] = []
    for line_no, line in _iter_lines_with_offset(code, line_offset):
        for match in _PROTO_TRAVERSAL_RE.finditer(line):
            target = match.group("target")
            key = match.group("key").strip("'\"")
            value = match.group("value").strip()
            findings.append(
                PrototypePollutionFinding(
                    url=url,
                    line=line_no,
                    pattern=f"{target}[{key}] = {value}",
                    pattern_type="traversal",
                    severity="high",
                    context=_truncate_context(line),
                    target=target,
                    key=key,
                    value=value,
                )
            )
        for match in _PROTO_ASSIGN_RE.finditer(line):
            target = match.group("target")
            key = match.group("key")
            value = match.group("value").strip()
            findings.append(
                PrototypePollutionFinding(
                    url=url,
                    line=line_no,
                    pattern=f"{target}.{key} = {value}",
                    pattern_type="assign",
                    severity="high",
                    context=_truncate_context(line),
                    target=target,
                    key=key,
                    value=value,
                )
            )
        for match in _JSON_MERGE_FUNCS.finditer(line):
            fn = match.group("fn")
            findings.append(
                PrototypePollutionFinding(
                    url=url,
                    line=line_no,
                    pattern=f"merge_helper:{fn}",
                    pattern_type="merge",
                    severity="medium",
                    context=_truncate_context(line),
                )
            )
        for regex, name, severity in _PROTO_RE:
            if regex.search(line):
                findings.append(
                    PrototypePollutionFinding(
                        url=url,
                        line=line_no,
                        pattern=name,
                        pattern_type="merge"
                        if name == "custom_merge" or name == "deepMerge"
                        else "pattern",
                        severity=severity,
                        context=_truncate_context(line),
                    )
                )
    return findings


def walk_html(html: str, *, url: str) -> list[PrototypePollutionFinding]:
    from src.detection.ast.js_sink_analyzer import fetch_inline_scripts

    findings: list[PrototypePollutionFinding] = []
    for line_offset, code in fetch_inline_scripts(html):
        findings.extend(walk_script(code, url=url, line_offset=line_offset))
    return findings


# ---------------------------------------------------------------------------
# Data-shape analysis (e.g. JSON config / object-graph analysis)
# ---------------------------------------------------------------------------


def analyze_object(
    obj: Any,
    *,
    url: str,
    path: str = "$",
    depth: int = 0,
    max_depth: int = 16,
) -> list[PrototypePollutionFinding]:
    """Recursively analyze a JSON-like object for prototype pollution surface.

    Identifies keys that would map to ``__proto__``, ``constructor`` or
    ``prototype`` if the object is later merged with another via a
    deep-merge helper.
    """

    findings: list[PrototypePollutionFinding] = []
    if depth >= max_depth:
        return findings
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                continue
            if key in {"__proto__", "constructor", "prototype"}:
                findings.append(
                    PrototypePollutionFinding(
                        url=url,
                        line=depth + 1,
                        pattern=f"object:{path}.{key}",
                        pattern_type="object_key",
                        severity="high",
                        context=f"{path}.{key}",
                        target=path,
                        key=key,
                        value=str(value)[:200],
                    )
                )
            if isinstance(value, (dict, list)):
                findings.extend(
                    analyze_object(
                        value,
                        url=url,
                        path=f"{path}.{key}",
                        depth=depth + 1,
                        max_depth=max_depth,
                    )
                )
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                findings.extend(
                    analyze_object(
                        item,
                        url=url,
                        path=f"{path}[{index}]",
                        depth=depth + 1,
                        max_depth=max_depth,
                    )
                )
    return findings


def analyze_json_string(text: str, *, url: str) -> list[PrototypePollutionFinding]:
    try:
        return analyze_object(json.loads(text), url=url)
    except (json.JSONDecodeError, ValueError):
        return []


__all__ = [
    "PrototypePollutionFinding",
    "walk_script",
    "walk_html",
    "analyze_object",
    "analyze_json_string",
]
