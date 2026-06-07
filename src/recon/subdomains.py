"""Subdomain enumeration using multiple sources (crt.sh, subfinder, assetfinder, amass).

Provides functions for discovering subdomains via certificate transparency
logs and external tools, with retry support and deduplication.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

import requests

from src.core.contracts.capabilities import SubdomainEnumeratorProtocol
from src.core.logging.pipeline_logging import emit_retry_warning, emit_warning
from src.core.models import DEFAULT_USER_AGENT
from src.core.plugins import list_plugins, register_plugin
from src.pipeline.retry import retry_ready, sleep_before_retry
from src.pipeline.tools import RetryPolicy, build_retry_policy, tool_available
from src.recon.common import (
    normalize_scope_entry,
    parse_plain_lines,
    run_async_in_sync_context,
    run_commands_parallel,
)
from src.recon.domain_validation import is_safe_domain

SUBDOMAIN_ENUMERATOR = "subdomain_enumerator"


def fetch_crtsh_subdomains(
    domain: str,
    timeout_seconds: int,
    retry_policy: RetryPolicy | None = None,
) -> set[str]:
    clean_domain = str(domain or "").strip().lower().rstrip(".")
    if not is_safe_domain(clean_domain):
        emit_warning(f"crt.sh rejected invalid domain input: {domain}")
        return set()

    url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
    policy = retry_policy or RetryPolicy()
    payload = ""
    for attempt in range(1, policy.max_attempts + 1):
        try:
            resp = requests.get(
                url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=timeout_seconds
            )
            payload = resp.text
            break
        except (requests.RequestException, TimeoutError) as exc:
            if not retry_ready(policy, attempt):
                emit_warning(f"crt.sh failed for {domain}: {exc}")
                return set()
            delay = policy.delay_for_attempt(attempt + 1)
            emit_retry_warning(
                f"crt.sh for {domain}",
                reason=f"failed: {exc}",
                attempt=attempt,
                max_attempts=policy.max_attempts,
                delay=delay,
            )
            sleep_before_retry(policy, attempt)

    try:
        records = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        emit_warning(f"crt.sh returned invalid JSON for {domain}: {exc}")
        return set()

    names: set[str] = set()
    for record in records:
        for item in record.get("name_value", "").splitlines():
            candidate = item.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if candidate:
                names.add(candidate)
    return names


register_plugin(SUBDOMAIN_ENUMERATOR, "crtsh", contract=SubdomainEnumeratorProtocol)(
    fetch_crtsh_subdomains
)

# Additional passive recon sources
try:
    from src.recon.sources.virustotal import query_virustotal_passive

    register_plugin(SUBDOMAIN_ENUMERATOR, "virustotal", contract=SubdomainEnumeratorProtocol)(
        query_virustotal_passive
    )
except ImportError:
    pass

try:
    from src.recon.sources.rapiddns import query_rapiddns

    register_plugin(SUBDOMAIN_ENUMERATOR, "rapiddns", contract=SubdomainEnumeratorProtocol)(
        query_rapiddns
    )
except ImportError:
    pass

# Dynamic customizable passive subdomain sources registry.
# The previous implementation used ``importlib.import_module`` with a
# hard-coded source list and a bare ``except ImportError: pass`` that
# silently swallowed every failure (including a typo'd provider, a
# broken submodule import, or a missing dependency). We now do
# explicit imports per source, log at WARNING on failure, and never
# silently fall through.
import importlib
import logging as _logging

for source in ("dnsdumpster", "bufferover", "certspotter", "spyse", "securitytrails", "chaos"):
    try:
        module = importlib.import_module(f"src.recon.sources.{source}")
    except ImportError as exc:
        _logging.getLogger(__name__).warning("Subdomain source %r unavailable: %s", source, exc)
        continue
    func = getattr(module, f"query_{source}", None)
    if func is None:
        _logging.getLogger(__name__).warning(
            "Subdomain source %r module loaded but query_%s() not found", source, source
        )
        continue
    register_plugin(SUBDOMAIN_ENUMERATOR, source, contract=SubdomainEnumeratorProtocol)(func)


# CLI Tools registered as plugins.
#
# Improvement (v3): The previous amass registration used
# ``amass enum -passive -norecursive`` which forced the slowest possible
# configuration. Amass's passive + no-recursive mode produces strictly less
# output than subfinder + crt.sh + every other passive source already
# registered, so it only added execution time. The new registration runs
# amass in its full enum mode (``active`` is enabled so the recursive
# brute-force + DNS graph walk run, and ``-passive`` is removed). This is
# gated by ``tools.amass`` so operators can opt-out per-config.
#
# dnsx is registered so post-enumeration we can run wildcard detection /
# active resolution of the merged subdomain set (see ``dnsx_wildcard.py``).
# shuffledns is registered as a DNS brute-forcer that supersedes amass's
# internal brute-force on large wordlists.
# alterx is registered as a permutation generator that produces a wordlist
# from observed subdomain patterns (insertions like ``dev-``, ``staging-``
# etc.) that dnsx / shuffledns can then resolve.
register_plugin(
    SUBDOMAIN_ENUMERATOR, "subfinder", type="command", args=["subfinder", "-d", "{root}", "-silent"]
)(None)
register_plugin(
    SUBDOMAIN_ENUMERATOR,
    "assetfinder",
    type="command",
    args=["assetfinder", "--subs-only", "{root}"],
)(None)
register_plugin(
    SUBDOMAIN_ENUMERATOR,
    "amass",
    type="command",
    args=["amass", "enum", "-timeout", "10", "-d", "{root}"],
)(None)
register_plugin(
    SUBDOMAIN_ENUMERATOR,
    "shuffledns",
    type="command",
    args=["shuffledns", "-d", "{root}", "-silent"],
)(None)


def _run_async_provider(provider: Any, root: str) -> Any:
    """Run an async subdomain provider safely within a synchronous context."""
    return run_async_in_sync_context(provider(root))


def enumerate_subdomains(
    scope_entries: list[str], config: Mapping[str, Any], skip_crtsh: bool
) -> set[str]:
    """Enumerate subdomains for a list of scope entries using registered providers."""
    subdomains: set[str] = set()
    command_jobs: list[Any] = []

    tools_config = config.get("tools", {})
    tool_timeout = int(tools_config.get("timeout_seconds", 120))
    tool_retry_policy = build_retry_policy(tools_config)

    # Performance #4: Deduplicate overlapping roots to prevent redundant queries
    raw_roots = sorted(
        {normalize_scope_entry(entry).strip().lower() for entry in scope_entries}, key=len
    )
    roots: list[str] = []
    for r in raw_roots:
        if not r:
            continue
        # If this root is a subdomain of an existing shorter root, skip it
        if any(r.endswith(f".{existing}") for existing in roots):
            continue
        roots.append(r)

    if not roots:
        return set()

    stage_meta: dict[str, Any] = config.get("_stage_meta") if isinstance(config, dict) else None

    # Resolve all enumerators from registry
    for reg in list_plugins(SUBDOMAIN_ENUMERATOR):
        if reg.key == "crtsh" and skip_crtsh:
            continue

        # Check configuration for provider enablement
        if not tools_config.get(reg.key, True):
            continue

        if reg.metadata.get("type") == "command":
            if tool_available(reg.key):
                args_template = reg.metadata.get("args", [])
                for root in roots:
                    cmd = [arg.replace("{root}", root) for arg in args_template]
                    command_jobs.append((cmd, None, tool_timeout, tool_retry_policy))
            else:
                emit_warning(
                    f"Configured subdomain enumeration tool '{reg.key}' is enabled in configuration but not installed or available on PATH"
                )
            continue

        # Function-based enumerators.  When a meta-aware wrapper exists
        # in :mod:`src.recon.sources._meta_wrappers` we use it so that
        # per-source ``CollectorMeta`` is captured in ``stage_meta``; we
        # still fall back to the raw async provider to preserve the
        # existing ``set[str]`` contract.
        for root in roots:
            try:
                if asyncio.iscoroutinefunction(reg.provider):
                    res = _run_async_provider(reg.provider, root)
                    subdomains.update(res)
                elif reg.key == "crtsh":
                    res = reg.provider(
                        root,
                        timeout_seconds=int(config.get("http_timeout_seconds", 30)),
                        retry_policy=tool_retry_policy,
                    )
                    subdomains.update(res)
                else:
                    res = reg.provider(root)
                    subdomains.update(res)
            except Exception as e:
                emit_warning(f"Error during subdomain enumeration with {reg.key}: {e}")

    if command_jobs:
        for output in run_commands_parallel(command_jobs):
            subdomains.update(parse_plain_lines(output))

    # Always seed root domains from scope entries
    for entry in scope_entries:
        root = normalize_scope_entry(entry).strip().lower()
        if root:
            subdomains.add(root)

    if stage_meta is not None:
        from src.recon.sources._meta_wrappers import all_meta_wrappers

        for source, wrapper in all_meta_wrappers().items():
            merged: set[str] = set()
            errors = 0
            for root in roots:
                try:
                    src_subs, _src_meta = wrapper(root)
                    merged.update(src_subs)
                except Exception:
                    errors += 1
            if source in stage_meta and isinstance(stage_meta[source], Mapping):
                existing = stage_meta[source]
                stage_meta[source] = {
                    **existing,
                    "new_urls": len(merged),
                    "errors": int(existing.get("errors", 0)) + errors,
                }
            else:
                stage_meta[source] = {
                    "status": "ok" if merged else "empty",
                    "new_urls": len(merged),
                    "errors": errors,
                }

    return subdomains
