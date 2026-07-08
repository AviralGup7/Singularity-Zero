"""AST-aware extraction functions."""

from __future__ import annotations

import re

from src.recon.js_parsers.regex_extractors import (
    _BLOCK_COMMENT_RE,
    _FETCH_LIKE_RE,
    _LINE_COMMENT_RE,
    _STRING_RE,
)


def _strip_strings_and_comments(content: str) -> str:
    """Replace string literals and comments with placeholders of equal length."""

    def _blank(match: re.Match[str]) -> str:
        return " " * len(match.group(0))

    content = _BLOCK_COMMENT_RE.sub(_blank, content)
    content = _LINE_COMMENT_RE.sub(_blank, content)
    content = _STRING_RE.sub(_blank, content)
    return content


def _find_balanced_arg(content: str, start: int) -> tuple[str, int] | None:
    """Return the substring of the first balanced paren expression starting at *start*."""
    if start >= len(content) or content[start] != "(":
        return None
    depth = 0
    i = start
    in_str = False
    str_ch = ""
    in_template = False
    template_depth = 0
    while i < len(content):
        ch = content[i]
        if in_str:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if ch == str_ch:
                in_str = False
            i += 1
            continue
        if in_template:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if ch == "`":
                in_template = False
                i += 1
                continue
            if ch == "$" and i + 1 < len(content) and content[i + 1] == "{":
                template_depth += 1
                i += 2
                continue
            if ch == "}" and template_depth > 0:
                template_depth -= 1
                i += 1
                continue
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            str_ch = ch
            i += 1
            continue
        if ch == "`":
            in_template = True
            i += 1
            continue
        if ch == "/" and i + 1 < len(content) and content[i + 1] == "/":
            nl = content.find("\n", i)
            i = len(content) if nl == -1 else nl + 1
            continue
        if ch == "/" and i + 1 < len(content) and content[i + 1] == "*":
            end = content.find("*/", i + 2)
            i = len(content) if end == -1 else end + 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return content[start + 1 : i], i
        i += 1
    return None


def _split_args(args_blob: str) -> list[str]:
    """Split the top-level comma-separated arguments inside a balanced call."""
    if not args_blob:
        return []
    args: list[str] = []
    depth_paren = depth_bracket = depth_brace = 0
    in_str = False
    str_ch = ""
    current: list[str] = []
    for ch in args_blob:
        if in_str:
            current.append(ch)
            if ch == "\\" and current:
                continue
            if ch == str_ch:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            str_ch = ch
            current.append(ch)
            continue
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket -= 1
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace -= 1
        if ch == "," and depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


def extract_endpoint_calls(content: str) -> list[str]:
    """AST-aware extraction of fetch-like call argument strings."""
    candidates: list[str] = []
    for match in _FETCH_LIKE_RE.finditer(content or ""):
        paren_start = match.end() - 1
        balanced = _find_balanced_arg(content, paren_start)
        if not balanced:
            continue
        args_blob, _ = balanced
        if not args_blob:
            continue
        first_args = _split_args(args_blob)
        if not first_args:
            continue
        first = first_args[0]
        if first:
            candidates.append(first)
    return candidates


def _resolve_template_to_pattern(text: str) -> str:
    """Replace ``${expr}`` placeholders with ``{param}`` for safe URL emission."""
    return re.sub(r"\$\{[^}]+\}", "{param}", text or "")


def _resolve_call_endpoint(arg_expr: str, base_url: str) -> str | None:
    """Convert a fetch-like first argument to an absolute URL."""
    from src.recon.js_parsers.regex_extractors import _candidate_to_absolute_url

    if not arg_expr:
        return None
    string_match = re.search(r"""(['"`])((?:\\.|(?!\1).)*)\1""", arg_expr, re.DOTALL)
    if string_match:
        inner = string_match.group(2)
        normalized = _resolve_template_to_pattern(inner)
        return _candidate_to_absolute_url(normalized, base_url)
    concat_match = re.match(r"^(['\"`])([^'\"`]+)\1\s*\+\s*[A-Za-z_$][\w$]*", arg_expr)
    if concat_match:
        prefix = concat_match.group(2)
        normalized = _resolve_template_to_pattern(prefix) + "{param}"
        return _candidate_to_absolute_url(normalized, base_url)
    return None
