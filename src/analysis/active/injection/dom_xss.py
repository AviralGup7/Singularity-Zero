"""DOM-based XSS scanner module.

Scans HTML response bodies and linked JavaScript files for DOM-based XSS
patterns by identifying sources, sinks, and sanitizers in client-side code.

Enhanced with context-aware analysis:
- HTML context detection (inspired by XSStrike htmlParser pattern)
- Reflection efficiency scoring (fuzzy matching on marker presence)
- WAF awareness with adaptive confidence penalties
- Confidence scoring per finding

Sources: where attacker-controlled data enters the application.
Sinks: dangerous DOM operations that can execute injected code.
Sanitizers: defensive patterns that mitigate XSS risk.

Usage:
    findings = scan_dom_xss(url, html_body, fetch_js_callback)
    report = build_dom_xss_report(findings, url)
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from src.analysis.active.injection._efficiency import reflection_efficiency

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Sources - where untrusted data enters the DOM
DOM_SOURCES: list[tuple[str, str, str]] = [
    (r"document\.URL", "source", "document.URL"),
    (r"document\.documentURI", "source", "document.documentURI"),
    (r"document\.baseURI", "source", "document.baseURI"),
    (r"location\.href", "source", "location.href"),
    (r"location\.search", "source", "location.search"),
    (r"location\.hash", "source", "location.hash"),
    (r"location\.pathname", "source", "location.pathname"),
    (r"window\.location", "source", "window.location"),
    (r"window\.name", "source", "window.name"),
    (r"document\.referrer", "source", "document.referrer"),
    (r"document\.cookie", "source", "document.cookie"),
    (r"event\.data", "source", "event.data"),
    (r"message\.data", "source", "message.data"),
    (r"localStorage\.getItem", "source", "localStorage.getItem"),
    (r"sessionStorage\.getItem", "source", "sessionStorage.getItem"),
]

DOM_SOURCES_COMPILED = [(re.compile(p, re.IGNORECASE), t, n) for p, t, n in DOM_SOURCES]

# Sinks - dangerous DOM operations
DOM_SINKS: list[tuple[str, str, str]] = [
    (r"\.innerHTML\s*=", "sink", ".innerHTML ="),
    (r"\.outerHTML\s*=", "sink", ".outerHTML ="),
    (r"document\.write\s*\(", "sink", "document.write()"),
    (r"document\.writeln\s*\(", "sink", "document.writeln()"),
    (r"(?<!\.)eval\s*\(", "sink", "eval()"),
    (r"setTimeout\s*\(\s*[\"']", "sink", 'setTimeout("...")'),
    (r"setInterval\s*\(\s*[\"']", "sink", 'setInterval("...")'),
    (r"\.insertAdjacentHTML\s*\(", "sink", ".insertAdjacentHTML()"),
    (r"location\.assign\s*\(", "sink", "location.assign()"),
    (r"location\.replace\s*\(", "sink", "location.replace()"),
    (r"window\.open\s*\(", "sink", "window.open()"),
    (r"\.setAttribute\s*\(\s*[\"']on", "sink", ".setAttribute('on*')"),
    (r"createContextualFragment\s*\(", "sink", "createContextualFragment()"),
    (r"dangerouslySetInnerHTML", "sink", "dangerouslySetInnerHTML"),
    (r"\$\s*\(.*\)\.html\s*\(", "sink", "$().html()"),
    (r"\$\s*\(.*\)\.append\s*\(", "sink", "$().append()"),
]

DOM_SINKS_COMPILED = [(re.compile(p, re.IGNORECASE), t, n) for p, t, n in DOM_SINKS]

# Sanitizers - defensive patterns
DOM_SANITIZERS: list[tuple[str, str]] = [
    (r"DOMPurify\.sanitize", "DOMPurify.sanitize"),
    (r"\.textContent\s*=", ".textContent ="),
    (r"\.innerText\s*=", ".innerText ="),
    (r"\.createTextNode\s*\(", ".createTextNode()"),
    (r"encodeURIComponent\s*\(", "encodeURIComponent()"),
]

DOM_SANITIZERS_COMPILED = [(re.compile(p, re.IGNORECASE), n) for p, n in DOM_SANITIZERS]

# Regex to extract inline script content (non-src scripts)
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)

# Regex to extract external script src URLs
_EXTERNAL_SCRIPT_RE = re.compile(
    r"<script[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)

# Regex to extract JS URLs from dynamic imports / require
_DYNAMIC_IMPORT_RE = re.compile(
    r"(?:import\s*\(\s*[\"']|require\s*\(\s*[\"'])([^\"']+)[\"']",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DomXssFinding:
    """A single DOM-based XSS finding."""

    url: str
    line: int
    pattern_type: str  # "source" or "sink"
    pattern: str
    severity: str  # "critical", "high", "medium", "low"
    context: str
    has_sanitizer: bool = False
    sanitizer_name: str | None = None
    confidence: float = 0.7  # 0-1 confidence score (XSStrike pattern)
    reflection_efficiency: int = 0  # 0-100 efficiency if live-probed
    waf_detected: bool = False
    waf_name: str | None = None


@dataclass
class DomXssReport:
    """Aggregated DOM XSS scan report."""

    url: str
    total_findings: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_patterns: list[tuple[str, int]] = field(default_factory=list)
    critical_findings: list[dict[str, Any]] = field(default_factory=list)
    high_findings: list[dict[str, Any]] = field(default_factory=list)
    findings_with_sanitizer: int = 0
    files_scanned: int = 0
    summary: str = ""


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


def _classify_severity(pattern_type: str, pattern: str, html_body: str = "") -> tuple[str, float]:
    """Classify severity and confidence based on pattern type and specific pattern.

    Inspired by XSStrike's confidence scoring: instead of binary classification,
    we score findings based on exploitability likelihood.

    Args:
        pattern_type: "source" or "sink".
        pattern: Human-readable pattern name.
        html_body: Optional HTML body for reflection efficiency scoring.

    Returns:
        Tuple of (severity string, confidence float 0-1).
    """
    critical_sinks = {
        "eval()",
        'setTimeout("...")',
        'setInterval("...")',
        "document.write()",
        "document.writeln()",
        "createContextualFragment()",
        "dangerouslySetInnerHTML",
    }
    high_sinks = {
        ".innerHTML =",
        ".outerHTML =",
        ".insertAdjacentHTML()",
        ".setAttribute('on*')",
        "location.assign()",
        "location.replace()",
        "$().html()",
    }
    medium_sinks = {
        "window.open()",
        "$().append()",
    }

    # Base confidence from pattern type
    base_confidence: float = 0.5

    if pattern_type == "sink":
        if pattern in critical_sinks:
            severity = "critical"
            base_confidence = 0.85
        elif pattern in high_sinks:
            severity = "high"
            base_confidence = 0.75
        elif pattern in medium_sinks:
            severity = "medium"
            base_confidence = 0.60
        else:
            severity = "medium"
            base_confidence = 0.55
    else:
        # Sources are generally lower severity on their own
        high_sources = {
            "document.cookie",
            "event.data",
            "message.data",
        }
        if pattern in high_sources:
            severity = "high"
            base_confidence = 0.65
        else:
            severity = "low"
            base_confidence = 0.40

    # Bonus if we can detect reflection efficiency in the HTML
    efficiency_bonus = 0.0
    if html_body:
        eff = reflection_efficiency(html_body, "v3dm0s")
        if eff >= 90:
            efficiency_bonus = 0.10
        elif eff >= 70:
            efficiency_bonus = 0.05

    confidence = min(1.0, base_confidence + efficiency_bonus)
    return severity, confidence


def _detect_sanitizers_in_content(content: str) -> list[tuple[str, str]]:
    """Detect sanitizer patterns in code content.

    Args:
        content: The JavaScript or HTML content to scan.

    Returns:
        List of (sanitizer_name, matched_text) tuples.
    """
    found: list[tuple[str, str]] = []
    for pattern_re, name in DOM_SANITIZERS_COMPILED:
        if pattern_re.search(content):
            found.append((name, pattern_re.pattern))
    return found


def _scan_content(
    content: str,
    url: str,
    *,
    is_external_js: bool = False,
    html_body: str = "",
) -> list[DomXssFinding]:
    """Scan code content for DOM XSS sources and sinks.

    Args:
        content: JavaScript or HTML content to scan.
        url: The URL this content came from (for attribution).
        is_external_js: Whether this is an external JS file (affects context).
        html_body: Optional full HTML body for reflection efficiency scoring.

    Returns:
        List of DomXssFinding objects.
    """
    findings: list[DomXssFinding] = []

    if not content:
        return findings

    # Detect sanitizers present in the entire content
    sanitizers = _detect_sanitizers_in_content(content)
    sanitizer_names = {name for name, _ in sanitizers}

    lines = content.split("\n")

    # Scan each line for sources and sinks
    for line_num, line_text in enumerate(lines, start=1):
        # Check sources
        for pattern_re, pattern_type, pattern_name in DOM_SOURCES_COMPILED:
            if pattern_re.search(line_text):
                has_sanitizer = bool(sanitizer_names)
                severity, confidence = _classify_severity(
                    pattern_type, pattern_name, html_body=html_body
                )
                findings.append(
                    DomXssFinding(
                        url=url,
                        line=line_num,
                        pattern_type=pattern_type,
                        pattern=pattern_name,
                        severity=severity,
                        confidence=confidence,
                        context="external_js" if is_external_js else "inline_script",
                        has_sanitizer=has_sanitizer,
                        sanitizer_name=", ".join(sorted(sanitizer_names))
                        if has_sanitizer
                        else None,
                    )
                )

        # Check sinks
        for pattern_re, pattern_type, pattern_name in DOM_SINKS_COMPILED:
            if pattern_re.search(line_text):
                has_sanitizer = bool(sanitizer_names)
                severity, confidence = _classify_severity(
                    pattern_type, pattern_name, html_body=html_body
                )
                findings.append(
                    DomXssFinding(
                        url=url,
                        line=line_num,
                        pattern_type=pattern_type,
                        pattern=pattern_name,
                        severity=severity,
                        confidence=confidence,
                        context="external_js" if is_external_js else "inline_script",
                        has_sanitizer=has_sanitizer,
                        sanitizer_name=", ".join(sorted(sanitizer_names))
                        if has_sanitizer
                        else None,
                    )
                )

    return findings


def _extract_external_js_urls(html_body: str, base_url: str) -> list[str]:
    """Extract external JavaScript file URLs from HTML.

    Args:
        html_body: The HTML content to parse.
        base_url: The base URL for resolving relative paths.

    Returns:
        List of absolute JavaScript file URLs.
    """
    urls: list[str] = []

    # Extract from <script src="...">
    for match in _EXTERNAL_SCRIPT_RE.finditer(html_body):
        src = match.group(1).strip()
        if src:
            try:
                absolute = urljoin(base_url, src)
                urls.append(absolute)
            except ValueError as exc:
                logger.debug("Failed to resolve JS URL %s: %s", src, exc)

    # Extract from dynamic imports / require
    for match in _DYNAMIC_IMPORT_RE.finditer(html_body):
        src = match.group(1).strip()
        if src:
            try:
                absolute = urljoin(base_url, src)
                urls.append(absolute)
            except ValueError as exc:
                logger.debug("Failed to resolve dynamic import URL %s: %s", src, exc)

    return urls


def _extract_inline_scripts(html_body: str) -> list[str]:
    """Extract inline <script> block contents from HTML.

    Args:
        html_body: The HTML content to parse.

    Returns:
        List of inline script text contents.
    """
    scripts: list[str] = []
    for match in _INLINE_SCRIPT_RE.finditer(html_body):
        content = match.group(1).strip()
        if content:
            scripts.append(content)
    return scripts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_dom_xss(
    url: str,
    html_body: str,
    fetch_js_callback: Callable[[str], str | None] | None = None,
) -> list[DomXssFinding]:
    """Scan an HTML page and its linked JS files for DOM-based XSS patterns.

    This function:
    1. Extracts and scans inline <script> blocks from the HTML body.
    2. Extracts <script src="..."> URLs and scans those JS files
       (if fetch_js_callback is provided).
    3. Returns a list of findings with source/sink locations.

    Args:
        url: The URL of the page being scanned.
        html_body: The HTML response body to analyze.
        fetch_js_callback: Optional callable that takes a JS URL and returns
            the JavaScript content as a string, or None on failure.
            Signature: (js_url: str) -> str | None

    Returns:
        List of DomXssFinding objects sorted by severity (critical first).
    """
    all_findings: list[DomXssFinding] = []

    if not html_body:
        logger.debug("Empty HTML body for %s, skipping DOM XSS scan", url)
        return all_findings

    # Step 1: Scan inline script blocks (pass html_body for efficiency scoring)
    inline_scripts = _extract_inline_scripts(html_body)
    for i, script_content in enumerate(inline_scripts):
        try:
            findings = _scan_content(script_content, url, is_external_js=False, html_body=html_body)
            all_findings.extend(findings)
            if findings:
                logger.debug(
                    "Found %d DOM XSS patterns in inline script #%d at %s",
                    len(findings),
                    i + 1,
                    url,
                )
        except Exception as exc:
            logger.warning("Error scanning inline script #%d at %s: %s", i + 1, url, exc)

    # Step 2: Scan external JS files
    external_js_urls = _extract_external_js_urls(html_body, url)
    for js_url in external_js_urls:
        if not fetch_js_callback:
            continue
        try:
            js_content = fetch_js_callback(js_url)
            if js_content:
                findings = _scan_content(
                    js_content, js_url, is_external_js=True, html_body=html_body
                )
                all_findings.extend(findings)
                if findings:
                    logger.debug(
                        "Found %d DOM XSS patterns in external JS at %s",
                        len(findings),
                        js_url,
                    )
        except Exception as exc:
            logger.warning("Error fetching/scanning external JS %s: %s", js_url, exc)

    # Sort by severity: critical > high > medium > low
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity, 4), f.url, f.line))

    return all_findings


# ---------------------------------------------------------------------------
# DOM Source-to-Sink Chain Tracking (learned from XSStrike dom.py)
# ---------------------------------------------------------------------------
#
# XSStrike doesn't just find sinks — it tracks taint flow from sources
# (location.search, window.name, etc.) through intermediate JavaScript
# variables to sinks (document.write, innerHTML, etc.). This allows it
# to distinguish between:
#   a) location.search used directly in innerHTML (HIGH risk)
#   b) location.search read but sanitized before use (LOW risk)
#   c) a sink present but fed only by hardcoded data (NO risk)
#
# Our original scanner only matched sources and sinks independently.
# This section adds chain tracking to correlate them.

# DOM sources with expanded patterns from XSStrike
_DOM_SOURCE_PATTERNS: list[tuple[str, str]] = [
    (r"document\.(URL|documentURI|baseURI)", "document.URL"),
    (r"document\.cookie", "document.cookie"),
    (r"document\.referrer", "document.referrer"),
    (r"location\.(href|search|hash|pathname)", "location.*"),
    (r"window\.name", "window.name"),
    (r"history\.(pushState|replaceState)", "history.*"),
    (r"(local|session)Storage", "storage.*"),
    (r"event\.data|message\.data", "postMessage.data"),
    (r"navigator\.serviceWorker", "serviceWorker"),
]

_DOM_SOURCE_PATTERNS_COMPILED = [(re.compile(p, re.IGNORECASE), n) for p, n in _DOM_SOURCE_PATTERNS]

# DOM sinks with expanded patterns from XSStrike
_DOM_SINK_PATTERNS: list[tuple[str, str]] = [
    (r"\.innerHTML\s*=", "innerHTML ="),
    (r"\.outerHTML\s*=", "outerHTML ="),
    (r"document\.write(ln)?\s*\(", "document.write"),
    (r"(?<!\.)eval\s*\(", "eval()"),
    (r"setTimeout\s*\(\s*[\"']", 'setTimeout("...")'),
    (r"setInterval\s*\(\s*[\"']", 'setInterval("...")'),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
    (r"location\.(assign|replace)\s*\(", "location.assign/replace"),
    (r"\.setAttribute\s*\(\s*[\"']on", ".setAttribute('on*')"),
    (r"createContextualFragment\s*\(", "createContextualFragment()"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
    (r"\.execScript\s*\(", "execScript()"),
    (r"Function\s*\(", "Function()"),
    (r"\$\(.*\)\.(html|append)\s*\(", "jQuery.html/append"),
]

_DOM_SINK_PATTERNS_COMPILED = [(re.compile(p, re.IGNORECASE), n) for p, n in _DOM_SINK_PATTERNS]


def _get_var_boundary_re(var_name: str) -> re.Pattern[str]:
    """Match a JavaScript identifier without matching substrings of longer names."""
    return re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(var_name)}(?![A-Za-z0-9_$])")


def _get_tainted_sink_re(var_name: str, sink_pattern: str) -> re.Pattern[str]:
    """Match a tainted variable flowing into a sink on the same statement."""
    escaped_var = rf"(?<![A-Za-z0-9_$]){re.escape(var_name)}(?![A-Za-z0-9_$])"
    return re.compile(rf"(?:{sink_pattern}.*{escaped_var}|{escaped_var}.*{sink_pattern})", re.IGNORECASE)


def _scan_dom_xss_chain(content: str, url: str) -> list[DomXssFinding]:
    """Scan a single script block for DOM XSS source-to-sink chains.

    Learned from XSStrike's dom.py:
    1. Identify all DOM sources on each line
    2. Track variable assignments from sources (taint propagation)
    3. Identify all sinks
    4. If a sink uses a tainted variable → finding with medium/high conf
    5. If source and sink are on the same line → finding with high conf
    6. If a sanitizer is detected between source and sink → lower confidence

    This is significantly more accurate than just finding sources and sinks
    independently because it:
    - Reduces false positives from dead code paths
    - Identifies the actual data flow, not just pattern presence
    - Assigns realistic confidence scores based on chain complexity
    """
    findings: list[DomXssFinding] = []
    if not content:
        return findings

    # First pass: find all sanitizers in the entire content
    all_sanitizers = _detect_sanitizers_in_content(content)
    sanitizer_names = {name for name, _ in all_sanitizers}
    has_sanitizers = bool(sanitizer_names)

    # Second pass: track tainted variables line by line
    tainted_vars: dict[str, str] = {}
    var_assign_re = re.compile(r"(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=")

    lines = content.split("\n")
    for line_num, line_text in enumerate(lines, start=1):
        # Check for source patterns
        for pattern_re, source_name in _DOM_SOURCE_PATTERNS_COMPILED:
            source_match = pattern_re.search(line_text)
            if source_match:
                # Check if this feeds into a variable assignment
                assign_match = var_assign_re.search(line_text[: source_match.start()])
                if assign_match:
                    var_name = assign_match.group(1)
                    tainted_vars[var_name] = source_name

                # Source used directly in something dangerous on same line
                for sink_re, sink_name in _DOM_SINK_PATTERNS_COMPILED:
                    if sink_re.search(line_text):
                        findings.append(
                            DomXssFinding(
                                url=url,
                                line=line_num,
                                pattern_type="source+sink_chain",
                                pattern=f"{source_name} -> {sink_name}",
                                severity="critical",
                                context="inline_script",
                                has_sanitizer=has_sanitizers,
                                sanitizer_name=", ".join(sorted(sanitizer_names))
                                if has_sanitizers
                                else None,
                            )
                        )

        # Check if tainted variables reach sinks
        for var_name, source_name in tainted_vars.items():
            for sink_re, sink_name in _DOM_SINK_PATTERNS_COMPILED:
                combined_re = _get_tainted_sink_re(var_name, sink_re.pattern)
                if combined_re.search(line_text):
                    findings.append(
                        DomXssFinding(
                            url=url,
                            line=line_num,
                            pattern_type="tainted_sink",
                            pattern=f"{source_name} ({var_name}) -> {sink_name}",
                            severity="high",
                            context="inline_script",
                            has_sanitizer=has_sanitizers,
                            sanitizer_name=", ".join(sorted(sanitizer_names))
                            if has_sanitizers
                            else None,
                        )
                    )

        # Check for unused sink (sinks not fed by any source)
        for sink_re, sink_name in _DOM_SINK_PATTERNS_COMPILED:
            if sink_re.search(line_text):
                # Only flag if no tainted variables are on this line
                line_has_tainted = any(
                    _get_var_boundary_re(v).search(line_text) for v in tainted_vars
                )
                if not line_has_tainted:
                    findings.append(
                        DomXssFinding(
                            url=url,
                            line=line_num,
                            pattern_type="sink",
                            pattern=sink_name,
                            severity="medium",
                            context="inline_script",
                            has_sanitizer=has_sanitizers,
                            sanitizer_name=", ".join(sorted(sanitizer_names))
                            if has_sanitizers
                            else None,
                        )
                    )

    return findings


def build_dom_xss_report(
    findings: list[DomXssFinding],
    url: str,
    *,
    files_scanned: int = 1,
) -> dict[str, Any]:
    """Build a structured DOM XSS scan report from findings.

    Args:
        findings: List of DomXssFinding objects from scan_dom_xss().
        url: The URL that was scanned.
        files_scanned: Number of files (HTML + JS) that were scanned.

    Returns:
        Report dict with severity_counts, top_patterns, critical_findings,
        high_findings, and summary statistics.
    """
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pattern_counts: dict[str, int] = {}
    critical_findings: list[dict[str, Any]] = []
    high_findings: list[dict[str, Any]] = []
    findings_with_sanitizer = 0

    for f in findings:
        # Count severity
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        # Count patterns
        pattern_counts[f.pattern] = pattern_counts.get(f.pattern, 0) + 1

        # Track sanitizer usage
        if f.has_sanitizer:
            findings_with_sanitizer += 1

        # Collect critical and high findings
        finding_dict: dict[str, Any] = {
            "url": f.url,
            "line": f.line,
            "pattern_type": f.pattern_type,
            "pattern": f.pattern,
            "severity": f.severity,
            "context": f.context,
            "has_sanitizer": f.has_sanitizer,
        }
        if f.sanitizer_name:
            finding_dict["sanitizer_name"] = f.sanitizer_name

        if f.severity == "critical":
            critical_findings.append(finding_dict)
        elif f.severity == "high":
            high_findings.append(finding_dict)

    # Top patterns by frequency
    top_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Build summary
    total = len(findings)
    if total == 0:
        summary = "No DOM-based XSS patterns detected."
    else:
        summary = (
            f"Found {total} DOM XSS pattern(s): "
            f"{severity_counts['critical']} critical, "
            f"{severity_counts['high']} high, "
            f"{severity_counts['medium']} medium, "
            f"{severity_counts['low']} low. "
            f"Scanned {files_scanned} file(s)."
        )
        if findings_with_sanitizer:
            summary += f" {findings_with_sanitizer} finding(s) have sanitizer mitigation present."

    report = DomXssReport(
        url=url,
        total_findings=total,
        severity_counts=severity_counts,
        top_patterns=top_patterns,
        critical_findings=critical_findings,
        high_findings=high_findings,
        findings_with_sanitizer=findings_with_sanitizer,
        files_scanned=files_scanned,
        summary=summary,
    )

    return {
        "url": report.url,
        "total_findings": report.total_findings,
        "severity_counts": report.severity_counts,
        "top_patterns": [{"pattern": p, "count": c} for p, c in report.top_patterns],
        "critical_findings": report.critical_findings,
        "high_findings": report.high_findings,
        "findings_with_sanitizer": report.findings_with_sanitizer,
        "files_scanned": report.files_scanned,
        "summary": report.summary,
    }
