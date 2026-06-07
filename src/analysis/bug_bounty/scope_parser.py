"""Bug bounty scope parsing utilities.

Parses raw scope text from HackerOne and Bugcrowd program pages into
structured :class:`ProgramScope` objects.  Wildcard patterns are
expanded and out-of-scope exclusions are applied so downstream stages
can operate on a clean in-scope URL set.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Iterator


@dataclass(frozen=True)
class ProgramScope:
    """Normalised representation of a bug bounty program scope."""

    target_urls: set[str] = field(default_factory=set)
    wildcard_patterns: list[str] = field(default_factory=list)
    exclusions: set[str] = field(default_factory=set)
    out_of_scope: set[str] = field(default_factory=set)
    raw_scope_text: str = ""

    def in_scope_urls(self) -> set[str]:
        return expand_wildcards(self) - set(self.out_of_scope)


def _extract_urls(text: str) -> Iterator[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith("* "):
            line = line[2:].strip()
        for part in re.split(r"[\s,;|]+", line):
            candidate = part.strip()
            if not candidate:
                continue
            if candidate.startswith(("http://", "https://")):
                yield candidate.rstrip("/")
            elif "*" in candidate or "?" in candidate:
                yield candidate
            elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}", candidate):
                yield f"https://{candidate}".rstrip("/")


def parse_hackerone_scope(raw_scope: str) -> ProgramScope:
    urls: set[str] = set()
    wildcards: list[str] = []
    out_of_scope: set[str] = set()
    exclusions: set[str] = set()
    in_oo_section = False
    for raw_line in raw_scope.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower in {"out of scope", "out-of-scope", "out_of_scope"}:
            in_oo_section = True
            continue
        if lower in {"in scope", "in-scope", "in_scope"}:
            in_oo_section = False
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith("#"):
            continue
        for part in re.split(r"[\s,;|]+", line):
            candidate = part.strip()
            if not candidate:
                continue
            if in_oo_section:
                out_of_scope.add(candidate.rstrip("/"))
                continue
            if candidate.startswith(("http://", "https://")):
                urls.add(candidate.rstrip("/"))
            elif "*" in candidate or "?" in candidate:
                wildcards.append(candidate)
            elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}", candidate):
                urls.add(f"https://{candidate}".rstrip("/"))
    return ProgramScope(
        target_urls=urls,
        wildcard_patterns=wildcards,
        exclusions=exclusions,
        out_of_scope=out_of_scope,
        raw_scope_text=raw_scope,
    )


def parse_bugcrowd_scope(raw_scope: str) -> ProgramScope:
    urls: set[str] = set()
    wildcards: list[str] = []
    out_of_scope: set[str] = set()
    exclusions: set[str] = set()
    in_oo_section = False
    for raw_line in raw_scope.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower in {"out of scope", "out-of-scope", "out_of_scope", "exclusions"}:
            in_oo_section = True
            continue
        if lower in {"in scope", "in-scope", "in_scope", "targets"}:
            in_oo_section = False
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith("#"):
            continue
        for part in re.split(r"[\s,;|]+", line):
            candidate = part.strip()
            if not candidate:
                continue
            if in_oo_section:
                out_of_scope.add(candidate.rstrip("/"))
                continue
            if candidate.startswith(("http://", "https://")):
                urls.add(candidate.rstrip("/"))
            elif "*" in candidate or "?" in candidate:
                wildcards.append(candidate)
            elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}", candidate):
                urls.add(f"https://{candidate}".rstrip("/"))
    return ProgramScope(
        target_urls=urls,
        wildcard_patterns=wildcards,
        exclusions=exclusions,
        out_of_scope=out_of_scope,
        raw_scope_text=raw_scope,
    )


def expand_wildcards(scope: ProgramScope) -> set[str]:
    expanded = set(scope.target_urls)
    for pattern in scope.wildcard_patterns:
        if "*" in pattern:
            matched = fnmatch.filter(list(expanded) if not expanded else [], pattern)
            if matched:
                expanded.update(matched)
            else:
                expanded.add(pattern)
        else:
            expanded.add(pattern)
    return expanded


def filter_out_of_scope(urls: set[str], scope: ProgramScope) -> set[str]:
    in_scope = expand_wildcards(scope)
    out = set(scope.out_of_scope)
    for oos in out:
        filtered = {u for u in in_scope if not fnmatch.fnmatch(u, oos) and oos not in u}
        in_scope = filtered
    in_scope.update({u for u in urls if u not in out})
    return in_scope
