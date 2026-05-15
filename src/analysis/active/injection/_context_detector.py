"""HTML context detection for response analysis.

Detects where injected test markers appear in HTML responses and classifies
the execution context (html, attribute, script, comment, dead). This is
inspired by XSStrike's htmlParser approach but rewritten to fit the pipeline's
architecture and use cases.

The key insight: knowing WHERE input lands tells you WHAT payloads will work.
A reflection inside <title> needs completely different payloads than one
inside a JavaScript variable or an html attribute value.

Usage::

    detector = ContextDetector(html_response_body)
    contexts = detector.detect_all('v3dm0s')  # list of reflection contexts
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ContextType = Literal["html", "attribute", "script", "comment", "dead"]
QuoteStyle = Literal["", "'", '"', "`"] | None


@dataclass(frozen=True)
class ReflectionContext:
    """A single reflection point with its HTML context."""

    position: int
    context: ContextType
    tag: str | None = None
    attribute_name: str | None = None
    attribute_value_before_marker: str | None = None
    quote_style: QuoteStyle = None


NON_EXECUTABLE_TAGS = frozenset(
    [
        "title",
        "textarea",
        "noembed",
        "noscript",
        "style",
        "template",
    ]
)

_WHITESPACE_RE = re.compile(r"\s")
_ATTR_PARSE_RE = re.compile(r"([\w\-]+)\s*=\s*(?:(['\"`]))?(.*)$")
_ATTR_FLAG_RE = re.compile(r"([\w\-]+)(?:\s|$)")

_SCRIPT_RE = re.compile(r"(?s)(?i)<script[^>]*>(.*?)</script>")
_ATTRIBUTE_RE = re.compile(r"<[^>]*(v3dm0s)[^>]*>")
_HTML_RE = re.compile(r"v3dm0s")
_COMMENT_RE = re.compile(r"(?s)<!--[\s\S]*?(v3dm0s)[\s\S]*?-->")
_BAD_CONTEXT_RE = re.compile(
    r"(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[\s\S]*?(v3dm0s)[\s\S]*?</\1>"
)


def _extract_scripts(html: str) -> list[tuple[int, str]]:
    """Return list of (start_position, script_content) tuples."""
    results = []
    for m in _SCRIPT_RE.finditer(html):
        results.append((m.start(1), m.group(1)))
    return results


class ContextDetector:
    """Detects reflection contexts in an HTML response."""

    def __init__(self, html: str, marker: str = "v3dm0s") -> None:
        self._html = html
        self._marker = marker
        self._clean_html = re.sub(r"<!--[\s\S]*?-->", "", html)

    def detect_all(self, marker: str | None = None) -> list[ReflectionContext]:
        """Detect all reflection contexts for the marker in the response."""
        mk = marker or self._marker
        html = self._html
        if mk != "v3dm0s":
            html = html.replace(mk, "v3dm0s")
            self._clean_html = re.sub(r"<!--[\s\S]*?-->", "", html)

        contexts: dict[int, ReflectionContext] = {}

        # 1. Check script contexts (highest priority - most dangerous)
        for start, content in _extract_scripts(html):
            idx = content.find(mk)
            if idx >= 0:
                abs_pos = start + idx
                _find_js_closer(content[:idx])
                quote = _detect_quote(content, idx, mk)
                tag_name = "script"
                contexts[abs_pos] = ReflectionContext(
                    position=abs_pos,
                    context="script",
                    tag=tag_name,
                    quote_style=quote,
                )

        # 2. Check attribute contexts
        if len(contexts) < html.count(mk):
            for m in _ATTRIBUTE_RE.finditer(self._clean_html):
                full_match = m.group(0)
                abs_pos = m.start(1)
                parts = _WHITESPACE_RE.split(full_match)
                tag_name = parts[0][1:] if parts else "unknown"
                attr_info = _parse_attribute(full_match, mk)
                contexts[abs_pos] = ReflectionContext(
                    position=abs_pos,
                    context="attribute",
                    tag=tag_name,
                    attribute_name=attr_info.get("name"),
                    attribute_value_before_marker=attr_info.get("value_before"),
                    quote_style=attr_info.get("quote"),
                )

        # 3. Check bare HTML contexts
        if len(contexts) < html.count(mk):
            for m in _HTML_RE.finditer(self._clean_html):
                abs_pos = m.start()
                if abs_pos not in contexts:
                    contexts[abs_pos] = ReflectionContext(
                        position=abs_pos,
                        context="html",
                    )

        # 4. Check comment contexts
        for m in _COMMENT_RE.finditer(html):
            abs_pos = m.start(1)
            if abs_pos not in contexts:
                contexts[abs_pos] = ReflectionContext(
                    position=abs_pos,
                    context="comment",
                )

        # Mark dead (non-executable) contexts
        for bad in _BAD_CONTEXT_RE.finditer(html):
            bad_tag = bad.group(1)
            for pos, ctx in list(contexts.items()):
                if bad.start() < pos < bad.end():
                    contexts[pos] = ReflectionContext(
                        position=pos,
                        context="dead",
                        tag=bad_tag,
                    )

        return sorted(contexts.values(), key=lambda c: c.position)

    def count_reflections(self, marker: str | None = None) -> int:
        """Count total number of marker reflections."""
        mk = marker or self._marker
        return self._html.count(mk)

    def has_reflection(self, marker: str | None = None) -> bool:
        return self.count_reflections(marker) > 0

    @property
    def total_reflections(self) -> int:
        return self.count_reflections()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _find_js_closer(pre: str) -> str:
    """From the text before the marker in a script, find what chars need to
    be emitted to close open JS structures (similar to XSStrike jsContexter)."""
    pre = re.sub(r"(?s)\{.*?\}|\(.*?\)|\".*?\"|'.*?'", "", pre)
    breaker = ""
    for char in pre:
        if char == "{":
            breaker += "}"
        elif char == "(":
            breaker += ";)"
        elif char == "[":
            breaker += "]"
        elif char == "}":
            breaker = breaker.rstrip("}")
        elif char == ")":
            breaker = breaker.rstrip(")")
        elif char == "]":
            breaker = breaker.rstrip("]")
    return breaker[::-1]


def _detect_quote(content: str, idx: int, marker: str) -> QuoteStyle:
    """Detect what quote (if any) wraps the marker in script content."""
    start = max(0, idx - 5)
    end = min(len(content), idx + len(marker) + 5)
    window = content[start:end]
    for ch in ["'", '"', "`"]:
        if ch in window:
            return ch
    return None


def _parse_attribute(tag_html: str, marker: str) -> dict[str, str | QuoteStyle]:
    """Parse attribute details from a tag containing the marker."""
    result: dict[str, str | QuoteStyle] = {}
    parts = tag_html.split(marker)
    if len(parts) < 2:
        return result

    before = parts[0]

    attr_match = _ATTR_PARSE_RE.search(before)
    if attr_match:
        result["name"] = attr_match.group(1)
        result["quote"] = attr_match.group(2)
        val_start = attr_match.group(3) or ""
        result["value_before"] = (val_start + marker).rstrip('">')
    else:
        flag_match = _ATTR_FLAG_RE.search(before[-50:])
        if flag_match:
            result["name"] = flag_match.group(1)
            result["value_before"] = marker
            result["quote"] = None

    return result
