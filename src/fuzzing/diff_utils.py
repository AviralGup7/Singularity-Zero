import re
import difflib
from typing import Any


_DYNAMIC_VALUE_PATTERNS = [
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
    r'\b1[0-9]{9}(\.\d+)?\b',
    r'\b1[0-9]{12}\b',
    r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT',
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
    r'\bnonce[_-]?[a-zA-Z0-9+/=]{16,}\b',
    r'\bnonce["\'\s:=]+[a-zA-Z0-9+/=]{16,}',
    r'\btimestamp["\'\s:=]+[a-zA-Z0-9-:, ]{8,}',
    r'\brequest[_-]?id["\'\s:=]+[a-zA-Z0-9-]{8,}',
    r'\breq[_-]?id["\'\s:=]+[a-zA-Z0-9-]{8,}',
    r'\btrace[_-]?id["\'\s:=]+[a-zA-Z0-9-]{16,}',
    r'\bspan[_-]?id["\'\s:=]+[a-zA-Z0-9-]{16,}',
    r'\bx-request-id["\'\s:=]+[a-zA-Z0-9-]{8,}',
    r'\bx-csrf["\'\s:=]+[a-zA-Z0-9+/=]{16,}',
    r'\bcsrf[_-]?token["\'\s:=]+[a-zA-Z0-9+/=]{16,}',
    r'\bsession[_-]?id["\'\s:=]+[a-zA-Z0-9-]{8,}',
    r'\bcache["\'\s:=]+[a-zA-Z0-9-]{8,}',
    r'\betag["\'\s:=]+[a-zA-Z0-9"-]{8,}',
    r'\blast[_-]?modified["\'\s:=]+[a-zA-Z0-9-:, ]{8,}',
    r'\bdate["\'\s:=]+[a-zA-Z0-9-:, ]{8,}',
    r'\bserver["\'\s:=]+[a-zA-Z0-9-]{8,}',
    r'\b[a-zA-Z0-9+/=]{32,}\b',
    r'\b[0-9a-fA-F]{16,}\b',
]

DYNAMIC_FIELD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _DYNAMIC_VALUE_PATTERNS]

_DYNAMIC_HEADER_KEYS = [
    'timestamp', 'nonce', 'request_id', 'req_id', 'trace_id', 'span_id',
    'x_request_id', 'x_csrf', 'csrf_token', 'session_id', 'cache', 'etag',
    'last_modified', 'date', 'server', 'set_cookie', 'x_powered_by',
]

_HEADER_STRIP_PATTERNS = [
    re.compile(r'^' + re.escape(k).replace('_', '[_-]?') + r'[\s:].*$', re.IGNORECASE | re.MULTILINE)
    for k in _DYNAMIC_HEADER_KEYS
]


def normalize_response(body: str, headers: dict[str, str] | None = None) -> str:
    normalized = body
    for pattern in DYNAMIC_FIELD_PATTERNS:
        normalized = pattern.sub('<DYNAMIC>', normalized)
    for pattern in _HEADER_STRIP_PATTERNS:
        normalized = pattern.sub('', normalized)
    return normalized


def strip_dynamic_headers(headers: dict[str, str]) -> dict[str, str]:
    dynamic_key_patterns = [
        re.compile(
            r'^(?:timestamp|nonce|request[_-]?id|req[_-]?id|trace[_-]?id|span[_-]?id'
            r'|x-request-id|x-csrf[_-]?token|csrf[_-]?token|session[_-]?id'
            r'|cache|etag|last[_-]?modified|date|server|set-cookie|x-powered-by)$',
            re.IGNORECASE,
        )
    ]
    return {k: v for k, v in headers.items() if not any(p.match(k) for p in dynamic_key_patterns)}


def compute_diff_ratio(baseline: str, candidate: str) -> float:
    return difflib.SequenceMatcher(None, baseline, candidate).ratio()


def find_byte_level_diffs(baseline: str, candidate: str, context_bytes: int = 32) -> list[dict[str, Any]]:
    baseline_lines = baseline.splitlines(keepends=True)
    candidate_lines = candidate.splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(baseline_lines, candidate_lines, lineterm=''))

    if not diff_lines:
        return []

    hunks: list[dict[str, Any]] = []
    current: list[str] = []
    hunk_index = 0

    for line in diff_lines:
        if line.startswith('---') or line.startswith('+++'):
            continue
        if line.startswith('@@'):
            if current:
                hunk_index += 1
                hunks.append(_build_hunk(current, hunk_index, context_bytes))
                current = []
        current.append(line)

    if current:
        hunk_index += 1
        hunks.append(_build_hunk(current, hunk_index, context_bytes))

    return hunks


def _build_hunk(diff_lines: list[str], hunk_index: int, context_bytes: int) -> dict[str, Any]:
    baseline_parts: list[str] = []
    candidate_parts: list[str] = []
    diff_size = 0

    for line in diff_lines:
        if line.startswith('-') and not line.startswith('---'):
            baseline_parts.append(line[1:])
            diff_size += max(1, len(line) - 1)
        elif line.startswith('+') and not line.startswith('+++'):
            candidate_parts.append(line[1:])
            diff_size += max(1, len(line) - 1)

    context_limit = context_bytes * 4
    baseline_context = ''.join(baseline_parts)[:context_limit]
    candidate_context = ''.join(candidate_parts)[:context_limit]

    return {
        'hunk_index': hunk_index,
        'baseline_context': baseline_context,
        'candidate_context': candidate_context,
        'diff_size': diff_size,
    }
