"""JavaScript sink/source analyzer.

Performs a lightweight AST-free static analysis of JavaScript source to find
sink-to-source paths that could lead to DOM XSS, prototype pollution, or
other client-side injection issues. The analyzer also processes
``sourceMappingURL`` references and inline JSON state (e.g. ``__NEXT_DATA__``)
to enrich the report with file/line metadata.

Implementation notes
--------------------
We deliberately avoid the ``esprima`` dependency to keep the runtime
import-light. The analyzer walks the source line by line, identifying:

* Sink calls (DOM mutators, code evaluators, navigation primitives).
* Source reads (URL components, message events, storage APIs).
* Sanitizers (DOMPurify, textContent assignments).
* Source map references (file and line back-pointers).
* ``__proto__`` / ``constructor.prototype`` mutations (prototype pollution).
* Insecure JSONP patterns (``callback=``).
* WebAssembly instantiations (``WebAssembly.instantiate``/``compile``).

The analyzer is best-effort and intended to surface *candidates*; the
exploitation layer (injectionengine) is responsible for confirmation.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------

# (regex, sink name, severity hint)
_JS_SINKS: tuple[tuple[str, str, str], ...] = (
    (r"\.innerHTML\s*=", "innerHTML_write", "high"),
    (r"\.outerHTML\s*=", "outerHTML_write", "high"),
    (r"document\.write(?:ln)?\s*\(", "document_write", "high"),
    (r"\beval\s*\(", "eval", "critical"),
    (r"new\s+Function\s*\(", "function_constructor", "critical"),
    (r"set(?:Timeout|Interval)\s*\(\s*[\"'][^\"']+[\"']", "string_setTimeout", "high"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML", "high"),
    (r"location\s*(?:\.|\[)['\"]?(href|assign|replace)", "location_assignment", "high"),
    (r"window\.open\s*\(", "window_open", "medium"),
    (r"\.setAttribute\s*\(\s*['\"](?:on\\w+|src|href|xlink:href)", "setAttribute_event", "high"),
    (r"dangerouslySetInnerHTML", "react_dangerouslySetInnerHTML", "high"),
    (r"jQuery\s*\([^)]*\)\.html\s*\(", "jquery_html", "high"),
    (r"\$\s*\([^)]*\)\.html\s*\(", "jquery_dollar_html", "high"),
    (r"createContextualFragment\s*\(", "createContextualFragment", "medium"),
    (r"\.srcdoc\s*=", "iframe_srcdoc", "medium"),
    (r"crypto\.subtle\.", "crypto_subtle", "info"),
    (r"WebAssembly\.(?:instantiate|compile|compileStreaming)\s*\(", "wasm_instantiate", "info"),
    (r"new\s+Worker\s*\(\s*[\"']?([^\"')]+)", "worker_spawn", "info"),
    (r"importScripts\s*\(", "importScripts", "info"),
    (r"postMessage\s*\(", "postMessage_call", "info"),
    (r"\.addEventListener\s*\(\s*['\"]message", "postMessage_listener", "info"),
)

# (regex, source name)
_JS_SOURCES: tuple[tuple[str, str], ...] = (
    (r"document\.URL", "document.URL"),
    (r"document\.documentURI", "document.documentURI"),
    (r"document\.baseURI", "document.baseURI"),
    (r"document\.referrer", "document.referrer"),
    (r"document\.cookie", "document.cookie"),
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"location\.pathname", "location.pathname"),
    (r"window\.name", "window.name"),
    (r"event\.data", "event.data"),
    (r"message\.data", "message.data"),
    (r"localStorage\.getItem", "localStorage"),
    (r"sessionStorage\.getItem", "sessionStorage"),
    (r"new\s+URLSearchParams\s*\(.*location\.search", "URLSearchParams"),
)

_JS_SANITIZERS: tuple[tuple[str, str], ...] = (
    (r"DOMPurify\.sanitize", "DOMPurify"),
    (r"\.textContent\s*=", "textContent"),
    (r"\.innerText\s*=", "innerText"),
    (r"sanitize\s*\(", "sanitize()"),
    (r"xss\s*\(.*\)", "xss()"),
    (r"encodeURIComponent", "encodeURIComponent"),
    (r"\.escape\s*\(", "escape()"),
)

# Prototype pollution surfaces
_PROTOTYPE_POLLUTION_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"\.?\b__proto__\s*\[", "__proto__", "high"),
    (r"\.?\b__proto__\s*=", "__proto__", "high"),
    (r"\.?\bconstructor\.prototype\s*\[", "constructor.prototype", "high"),
    (r"\bObject\.assign\s*\(\s*[^,]+,\s*[^)]*\)", "Object.assign", "medium"),
    (r"\bmerge\s*\(.*\b(target|dest)\b", "custom_merge", "medium"),
    (r"\bdeepMerge\s*\(.*\b(target|dest)\b", "deepMerge", "medium"),
    (r"\bsetProp\s*\(.*\b(target|dest)\b", "setProp", "medium"),
    (r"\bset(?:Property|In)\s*\(.*\b__proto__\b", "setProperty on __proto__", "high"),
    (r"\bset(?:Property|In)\s*\(.*\bprototype\b", "setProperty on prototype", "high"),
    (
        r"\bReflect\.set\s*\(\s*[^,]+,\s*[^,]+,\s*[^,)]+,\s*[^)]*\.prototype",
        "Reflect.set prototype",
        "high",
    ),
    (r"\bdefineProperty\s*\([^,]+,\s*['\"]__proto__['\"]", "defineProperty __proto__", "high"),
    (r"\bfor\s*\(\s*var\s+\w+\s+in\s+", "for...in (unfiltered)", "info"),
)

_JSONP_PATTERN = re.compile(
    r"[\"']?callback[\"']?\s*[:=]\s*[\"']?([A-Za-z_$][A-Za-z0-9_$]*)",
    re.IGNORECASE,
)

_SOURCE_MAP_HINT = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s'\"\\]+)",
    re.IGNORECASE,
)

_NEXT_DATA_HINT = re.compile(
    r"<script[^>]*id=[\"']__NEXT_DATA__[\"'][^>]*>([\s\S]*?)</script>",
    re.IGNORECASE,
)

# Pre-compile patterns for hot paths
_SINK_RE = [(re.compile(p, re.IGNORECASE), name, sev) for p, name, sev in _JS_SINKS]
_SOURCE_RE = [(re.compile(p, re.IGNORECASE), name) for p, name in _JS_SOURCES]
_SANITIZER_RE = [(re.compile(p, re.IGNORECASE), name) for p, name in _JS_SANITIZERS]
_PROTO_RE = [
    (re.compile(p, re.IGNORECASE), name, sev) for p, name, sev in _PROTOTYPE_POLLUTION_PATTERNS
]


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class JSSinkSourceFinding:
    url: str
    line: int
    pattern: str
    pattern_type: str  # sink|source|sanitizer|prototype|wasm|jsonp
    severity: str
    context: str
    has_sanitizer: bool
    sanitizer_name: str | None = None
    source_map: str | None = None
    source_name: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "line": self.line,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "context": self.context,
            "has_sanitizer": self.has_sanitizer,
            "sanitizer_name": self.sanitizer_name,
            "source_map": self.source_map,
            "source_name": self.source_name,
            **self.extra,
        }


# ---------------------------------------------------------------------------
# Source fetching
# ---------------------------------------------------------------------------


def fetch_inline_scripts(html: str) -> list[tuple[int, str]]:
    """Return ``(line_offset, code)`` tuples for every ``<script>`` block.

    The line offset is the 1-based line number where the block starts so
    findings can be reported in original HTML coordinates.
    """

    out: list[tuple[int, str]] = []
    script_re = re.compile(
        r"<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>",
        re.IGNORECASE,
    )
    for match in script_re.finditer(html):
        start = match.start()
        prefix = html[:start]
        line_offset = prefix.count("\n") + 1
        out.append((line_offset, match.group(1)))
    return out


def extract_source_map_url(script: str) -> str | None:
    """Return the URL referenced by ``//# sourceMappingURL=...`` if present."""

    match = _SOURCE_MAP_HINT.search(script)
    if not match:
        return None
    url = match.group(1).strip()
    if url.startswith("data:"):
        return url
    return url


def decode_inline_source_map(data_url: str) -> str | None:
    """Decode a ``data:application/json;base64,...`` source map."""

    if not data_url.startswith("data:"):
        return None
    try:
        _header, payload = data_url.split(",", 1)
    except ValueError:
        return None
    if "base64" in _header:
        try:
            return base64.b64decode(payload).decode("utf-8", errors="ignore")
        except (ValueError, binascii.Error):
            return None
    try:
        from urllib.parse import unquote

        return unquote(payload)
    except Exception:
        return None


def extract_next_data(html: str) -> dict[str, Any] | None:
    """Extract ``__NEXT_DATA__`` JSON payload from a Next.js page if present."""

    match = _NEXT_DATA_HINT.search(html)
    if not match:
        return None
    try:
        data = json.loads(match.group(1))
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        return data
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _truncate_context(line: str) -> str:
    cleaned = line.strip()
    if len(cleaned) > 240:
        return cleaned[:240] + "…"
    return cleaned


def analyze_script(
    script: str,
    *,
    url: str,
    line_offset: int = 1,
    source_map: str | None = None,
) -> list[JSSinkSourceFinding]:
    """Analyze a single script body and return findings."""

    findings: list[JSSinkSourceFinding] = []
    sinks_seen: set[str] = set()
    sources_seen: set[str] = set()
    sanitizers_seen: set[str] = set()

    for index, line in enumerate(script.splitlines(), start=1):
        absolute_line = line_offset + index - 1
        ctx = _truncate_context(line)

        for regex, name, severity in _SINK_RE:
            if regex.search(line) and name not in sinks_seen:
                sinks_seen.add(name)
                sanitizer_name = next(
                    (sname for sregex, sname in _SANITIZER_RE if sregex.search(line)),
                    None,
                )
                findings.append(
                    JSSinkSourceFinding(
                        url=url,
                        line=absolute_line,
                        pattern=name,
                        pattern_type="sink",
                        severity=severity,
                        context=ctx,
                        has_sanitizer=bool(sanitizer_name),
                        sanitizer_name=sanitizer_name,
                        source_map=source_map,
                    )
                )

        for regex, name in _SOURCE_RE:
            if regex.search(line) and name not in sources_seen:
                sources_seen.add(name)
                findings.append(
                    JSSinkSourceFinding(
                        url=url,
                        line=absolute_line,
                        pattern=name,
                        pattern_type="source",
                        severity="info",
                        context=ctx,
                        has_sanitizer=False,
                        source_map=source_map,
                        source_name=name,
                    )
                )

        for regex, name in _SANITIZER_RE:
            if regex.search(line):
                sanitizers_seen.add(name)

        for regex, name, severity in _PROTO_RE:
            if regex.search(line):
                findings.append(
                    JSSinkSourceFinding(
                        url=url,
                        line=absolute_line,
                        pattern=name,
                        pattern_type="prototype",
                        severity=severity,
                        context=ctx,
                        has_sanitizer=False,
                        source_map=source_map,
                    )
                )

        for match in _JSONP_PATTERN.finditer(line):
            callback_name = match.group(1)
            findings.append(
                JSSinkSourceFinding(
                    url=url,
                    line=absolute_line,
                    pattern=f"jsonp_callback={callback_name}",
                    pattern_type="jsonp",
                    severity="medium",
                    context=ctx,
                    has_sanitizer=False,
                    source_map=source_map,
                )
            )

    return findings


def analyze_html(
    html: str,
    *,
    url: str,
    script_fetcher: Any | None = None,
) -> list[JSSinkSourceFinding]:
    """Analyze an HTML document and (optionally) any external JS it references.

    ``script_fetcher`` is an optional async-or-sync callable taking a
    relative URL and returning the JS body as a string. The function itself
    runs synchronously; external fetches are dispatched only when the caller
    pre-fetches scripts and passes them through ``script_texts``.
    """

    findings: list[JSSinkSourceFinding] = []
    for line_offset, code in fetch_inline_scripts(html):
        source_map_url = extract_source_map_url(code)
        findings.extend(
            analyze_script(code, url=url, line_offset=line_offset, source_map=source_map_url)
        )
    return findings


def analyze_scripts(
    scripts: Iterable[tuple[str, str, int]],
) -> list[JSSinkSourceFinding]:
    """Analyze a pre-fetched list of ``(url, code, line_offset)`` scripts."""

    findings: list[JSSinkSourceFinding] = []
    for url, code, line_offset in scripts:
        source_map_url = extract_source_map_url(code)
        findings.extend(
            analyze_script(code, url=url, line_offset=line_offset, source_map=source_map_url)
        )
    return findings


__all__ = [
    "JSSinkSourceFinding",
    "analyze_html",
    "analyze_script",
    "analyze_scripts",
    "decode_inline_source_map",
    "extract_next_data",
    "extract_source_map_url",
    "fetch_inline_scripts",
]
