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
from src.recon.common import normalize_scope_entry, parse_plain_lines, run_commands_parallel

SUBDOMAIN_ENUMERATOR = "subdomain_enumerator"


def fetch_crtsh_subdomains(
    domain: str,
    timeout_seconds: int,
    retry_policy: RetryPolicy | None = None,
) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
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
    except json.JSONDecodeError as exc:
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


# CLI Tools registered as plugins
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
    args=["amass", "enum", "-passive", "-norecursive", "-d", "{root}"],
)(None)




def enumerate_subdomains(scope_entries: list[str], config: Mapping[str, Any], skip_crtsh: bool) -> set[str]:
    """Enumerate subdomains for a list of scope entries using registered providers."""
    subdomains: set[str] = set()
    command_jobs: list[Any] = []

    tools_config = config.get("tools", {})
    tool_timeout = int(tools_config.get("timeout_seconds", 120))
    tool_retry_policy = build_retry_policy(tools_config)
    roots = [normalize_scope_entry(entry) for entry in scope_entries]

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
            continue

        # Function-based enumerators
        for root in roots:
            try:
                if asyncio.iscoroutinefunction(reg.provider):
                    # For async providers, run in a temporary loop
                    loop = asyncio.new_event_loop()
                    try:
                        res = loop.run_until_complete(reg.provider(root))
                        subdomains.update(res)
                    finally:
                        loop.close()
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
                emit_warning(f"Error during subdomain enumeration with {reg.key}: {e}", module="recon.subdomains")

    if command_jobs:
        for output in run_commands_parallel(command_jobs):
            subdomains.update(parse_plain_lines(output))

    # Always seed root domains from scope entries
    for entry in scope_entries:
        root = normalize_scope_entry(entry).strip().lower()
        if root:
            subdomains.add(root)
    return subdomains
