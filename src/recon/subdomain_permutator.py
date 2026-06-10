"""Subdomain permutation engine (alterx-style).

The ``alterx`` tool by ProjectDiscovery generates a wordlist of
likely-alive subdomains by permuting the patterns observed in the
already-discovered subdomain set. For example, if you have found
``api-staging.example.com`` and ``api-prod.example.com``, alterx
will suggest ``api-dev.example.com``, ``api-test.example.com``, etc.

This module re-implements the core ``alterx`` logic in pure Python
so the recon pipeline can perform permutation generation without
requiring the Go binary:

1. Tokenise each known subdomain by ``-`` and ``.`` boundaries.
2. Extract the prefix tokens (everything before the registered
   domain) and group them by structural position.
3. Apply a permutation grammar:
   * Replace one prefix token with a synonym from the word list.
   * Insert a new prefix token at any boundary.
   * Swap two adjacent prefix tokens.
   * Wrap the entire prefix with a "staging" / "dev" / "test" tag.
4. Filter permutations that are not in scope (out-of-domain).
5. Optionally resolve the candidates via dnsx / shuffledns to
   prune DNS NXDOMAINs before they reach httpx.

The result is a set of candidate subdomains ready to feed into the
existing ``enumerate_subdomains`` pipeline.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.recon.domain_validation import normalize_domain

logger = logging.getLogger(__name__)


# Default synonym list. Operators can extend it via the
# ``permutator_extra_words`` config key.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "dev",
    "development",
    "stage",
    "staging",
    "stg",
    "qa",
    "uat",
    "test",
    "testing",
    "sandbox",
    "demo",
    "prod",
    "production",
    "prd",
    "live",
    "beta",
    "alpha",
    "canary",
    "internal",
    "intranet",
    "external",
    "public",
    "private",
    "v1",
    "v2",
    "v3",
    "v4",
    "api",
    "app",
    "web",
    "mobile",
    "backend",
    "frontend",
    "admin",
    "console",
    "dashboard",
    "portal",
    "eu",
    "us",
    "ap",
    "apac",
    "emea",
    "global",
    "old",
    "new",
    "legacy",
    "next",
    "preview",
    "pr",
    "ci",
    "cd",
    "build",
    "deploy",
    "release",
    "blue",
    "green",
    "edge",
    "origin",
    "lb",
    "cdn",
)

# Delimiters used to tokenise subdomain prefixes.
_DELIMITER_RE = re.compile(r"[._-]")


@dataclass
class PermutationResult:
    """Output of the permutator."""

    domain: str
    seed_subdomains: set[str] = field(default_factory=set)
    permutations: set[str] = field(default_factory=set)
    permutations_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "seed_count": len(self.seed_subdomains),
            "permutations_count": self.permutations_count,
        }


def _tokenize(subdomain: str, domain: str) -> list[str]:
    """Tokenise a subdomain into prefix tokens.

    Example: ``api-staging.svc.eu.example.com`` with domain
    ``example.com`` -> ``["api", "staging", "svc", "eu"]``.
    """
    if not subdomain or subdomain == domain:
        return []
    bare = subdomain[: -len(domain)].rstrip(".")
    if not bare:
        return []
    return [t for t in _DELIMITER_RE.split(bare) if t]


# ---------------------------------------------------------------------------
# Permutation grammar
# ---------------------------------------------------------------------------


def _swap_adjacent(tokens: list[str]) -> list[list[str]]:
    """Generate every permutation that swaps two adjacent tokens."""
    out: list[list[str]] = []
    for i in range(len(tokens) - 1):
        new_tokens = list(tokens)
        new_tokens[i], new_tokens[i + 1] = new_tokens[i + 1], new_tokens[i]
        out.append(new_tokens)
    return out


def _insert_token(tokens: list[str], word: str) -> list[list[str]]:
    """Generate every permutation with *word* inserted at a boundary."""
    out: list[list[str]] = []
    for i in range(len(tokens) + 1):
        new_tokens = list(tokens)
        new_tokens.insert(i, word)
        out.append(new_tokens)
    return out


def _replace_token(tokens: list[str], word: str) -> list[list[str]]:
    """Generate every permutation that replaces one token with *word*."""
    out: list[list[str]] = []
    for i in range(len(tokens)):
        new_tokens = list(tokens)
        new_tokens[i] = word
        out.append(new_tokens)
    return out


def _prefix_wrap(tokens: list[str], word: str) -> list[list[str]]:
    """Generate ``word-tokens...`` permutations."""
    return [[word, *tokens]]


def _join_tokens(tokens: list[str]) -> str:
    return "-".join(tokens)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_permutations(
    subdomains: Iterable[str],
    domain: str,
    *,
    wordlist: Iterable[str] | None = None,
    max_results: int = 5000,
) -> PermutationResult:
    """Generate a set of candidate subdomains via permutation.

    Args:
        subdomains: Known subdomains for *domain* (the seed set).
        domain: Root domain (already normalised).
        wordlist: Override the synonym list.
        max_results: Cap on the returned permutation set size.

    Returns:
        Populated :class:`PermutationResult` with the candidates
        ready to be resolved via dnsx / shuffledns.
    """
    clean = normalize_domain(domain)
    result = PermutationResult(domain=clean)
    if not clean:
        return result

    seed_set: set[str] = set()
    tokenised: list[list[str]] = []
    for sub in subdomains:
        sub_clean = (sub or "").strip().lower().rstrip(".")
        if not sub_clean or sub_clean == clean:
            continue
        if not sub_clean.endswith(f".{clean}") and sub_clean != clean:
            continue
        seed_set.add(sub_clean)
        tokens = _tokenize(sub_clean, clean)
        if tokens:
            tokenised.append(tokens)
    result.seed_subdomains = seed_set
    if not tokenised:
        return result

    words = tuple(wordlist) if wordlist is not None else DEFAULT_WORDLIST
    candidates: set[str] = set()
    # Early bail-out threshold to prevent memory exhaustion on large seed sets.
    candidate_cap = max_results * 10
    for tokens in tokenised:
        for word in words:
            for perm in _replace_token(tokens, word):
                candidates.add(_join_tokens(perm) + "." + clean)
            for perm in _insert_token(tokens, word):
                candidates.add(_join_tokens(perm) + "." + clean)
            for perm in _prefix_wrap(tokens, word):
                candidates.add(_join_tokens(perm) + "." + clean)
            if len(candidates) > candidate_cap:
                break
        if len(candidates) > candidate_cap:
            break
        for perm in _swap_adjacent(tokens):
            candidates.add(_join_tokens(perm) + "." + clean)
        if len(candidates) > candidate_cap:
            break

    # Strip the seed set itself; we only want *new* candidates.
    candidates -= seed_set
    # Cap the result deterministically (sort then slice).
    sorted_candidates = sorted(candidates)
    if len(sorted_candidates) > max_results:
        sorted_candidates = sorted_candidates[:max_results]
    result.permutations = set(sorted_candidates)
    result.permutations_count = len(result.permutations)
    return result


# ---------------------------------------------------------------------------
# CLI wrapper (preferred path)
# ---------------------------------------------------------------------------


def run_alterx_cli(
    domain: str,
    *,
    timeout_seconds: int = 30,
    extra_args: list[str] | None = None,
) -> set[str]:
    """Run :command:`alterx` against a domain and return its output.

    The function is a thin wrapper that streams alterx's stdout
    back as a set of candidate hostnames. Empty when alterx is not
    installed.
    """
    from src.pipeline.tools import tool_available, try_command

    if not tool_available("alterx"):
        return set()
    args = ["alterx", "-d", domain, "-silent"]
    if extra_args:
        args.extend(extra_args)
    output = try_command(args, timeout=max(1, int(timeout_seconds)))
    return {
        line.strip().lower()
        for line in (output or "").splitlines()
        if line.strip() and not line.startswith("#")
    }


__all__ = [
    "DEFAULT_WORDLIST",
    "PermutationResult",
    "generate_permutations",
    "run_alterx_cli",
]
