"""Subdomain enumeration using multiple sources (crt.sh, subfinder, assetfinder, amass, findomain, SubdomainCenter, GitHub, GitLab, BinaryEdge).

Provides functions for discovering subdomains via certificate transparency
logs and external tools, with retry support and deduplication.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Mapping
from typing import Any

import requests

from src.core.contracts.capabilities import SubdomainEnumeratorProtocol
from src.core.logging.pipeline_logging import emit_retry_warning, emit_warning
from src.core.models import DEFAULT_USER_AGENT
from src.core.plugins import list_plugins, register_plugin
from src.core.tools.retry import retry_ready, sleep_before_retry
from src.pipeline.tools import RetryPolicy, build_retry_policy, tool_available
from src.recon.common import (
    normalize_scope_entry,
    parse_plain_lines,
    run_async_in_sync_context,
    run_commands_parallel,
)
from src.recon.domain_validation import is_safe_domain

SUBDOMAIN_ENUMERATOR = "subdomain_enumerator"

logger = logging.getLogger(__name__)


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
            # Strip leading wildcard prefixes (e.g., *., *.*., *..)
            while candidate.startswith("*."):
                candidate = candidate[2:]
            # Also strip any remaining leading dot or asterisk
            candidate = candidate.lstrip("*.")
            if candidate:
                names.add(candidate)
    return names


register_plugin(SUBDOMAIN_ENUMERATOR, "crtsh", contract=SubdomainEnumeratorProtocol)(
    fetch_crtsh_subdomains
)

try:
    from src.recon.sources.subdomain_center import query_subdomain_center

    register_plugin(SUBDOMAIN_ENUMERATOR, "subdomain_center", contract=SubdomainEnumeratorProtocol)(
        query_subdomain_center
    )
except ImportError as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001


def _fetch_findomain_subdomains(
    domain: str,
    timeout_seconds: int = 60,
) -> set[str]:
    if not tool_available("findomain"):
        return set()
    clean = str(domain or "").strip().lower().rstrip(".")
    if not clean:
        return set()
    try:
        from src.pipeline.tools import try_command

        output = try_command(
            ["findomain", "-t", clean, "-q"],
            timeout=timeout_seconds,
        )
        return {
            line.strip().lower()
            for line in (output or "").splitlines()
            if line.strip() and not any(c.isspace() for c in line.strip())
        }
    except Exception:
        logger.debug("findomain failed for %s", domain, exc_info=True)
        return set()


async def _fetch_github_code_search(
    domain: str,
    timeout_seconds: int = 30,
) -> set[str]:
    import os

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN")
    if not token:
        return set()
    clean = str(domain or "").strip().lower().rstrip(".")
    if not clean:
        return set()
    subdomains: set[str] = set()
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={
                "User-Agent": "cyber-pipeline/1.0",
                "Accept": "application/vnd.github.v3+json",
                "Authorization": f"token {token}",
            },
        ) as client:
            query = f"{clean}"
            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 50},
            )
            if resp.status_code == 403:
                return set()
            if resp.status_code != 200:
                return set()
            data = resp.json()
            for item in data.get("items") or []:
                for match in item.get("text_matches") or []:
                    frag = match.get("fragment") or ""
                    for line in frag.splitlines():
                        for token in line.split():
                            tok = token.strip().rstrip(".,;\"'`")
                            if tok.endswith(f".{clean}") and tok != clean:
                                subdomains.add(tok.lower())
    except Exception as exc:
        logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001
    return subdomains


async def _fetch_gitlab_search(
    domain: str,
    timeout_seconds: int = 30,
) -> set[str]:
    token = os.environ.get("GITLAB_TOKEN") or os.environ.get("GITLAB_API_TOKEN")
    if not token:
        return set()
    clean = str(domain or "").strip().lower().rstrip(".")
    if not clean:
        return set()
    subdomains: set[str] = set()
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={
                "User-Agent": "cyber-pipeline/1.0",
                "Private-Token": token,
            },
        ) as client:
            resp = await client.get(
                "https://gitlab.com/api/v4/search",
                params={"scope": "blobs", "search": clean, "per_page": 25},
            )
            if resp.status_code == 403:
                return set()
            if resp.status_code != 200:
                return set()
            data = resp.json()
            for item in data or []:
                snippet = item.get("data") or ""
                for line in snippet.splitlines():
                    for token in line.split():
                        tok = token.strip().rstrip(".,;\"'`")
                        if tok.endswith(f".{clean}") and tok != clean:
                            subdomains.add(tok.lower())
    except Exception as exc:
        logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001
    return subdomains


async def _fetch_binaryedge_passive(
    domain: str,
    timeout_seconds: int = 30,
) -> set[str]:
    token = os.environ.get("BINARYEDGE_API_KEY") or os.environ.get("BINARYEDGE_TOKEN")
    if not token:
        return set()
    clean = str(domain or "").strip().lower().rstrip(".")
    if not clean:
        return set()
    subdomains: set[str] = set()
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={
                "User-Agent": "cyber-pipeline/1.0",
                "X-Key": token,
            },
        ) as client:
            resp = await client.get(
                "https://api.binaryedge.io/v2/query/domains/subdomain",
                params={"domain": clean},
            )
            if resp.status_code == 403:
                return set()
            if resp.status_code != 200:
                return set()
            data = resp.json()
            events = data.get("events") or data.get("result") or []
            if isinstance(events, list):
                for entry in events:
                    if isinstance(entry, str):
                        cand = entry.strip().lower()
                    elif isinstance(entry, dict):
                        cand = (entry.get("domain") or entry.get("host") or "").strip().lower()
                    else:
                        continue
                    if cand and cand.endswith(f".{clean}") and cand != clean:
                        subdomains.add(cand)
    except Exception as exc:
        logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001
    return subdomains


class _FindomainBackend:
    @staticmethod
    def query(domain: str) -> set[str]:
        return _fetch_findomain_subdomains(domain)


class _SubdomainCenterBackend:
    @staticmethod
    def query(domain: str) -> set[str]:
        from src.recon.sources.subdomain_center import query_subdomain_center as _q

        return set(run_async_in_sync_context(_q(domain)))  # type: ignore[no-any-return]


class _GitHubSearchBackend:
    @staticmethod
    def query(domain: str) -> set[str]:
        return set(run_async_in_sync_context(_fetch_github_code_search(domain)))  # type: ignore[no-any-return]


class _GitLabSearchBackend:
    @staticmethod
    def query(domain: str) -> set[str]:
        return set(run_async_in_sync_context(_fetch_gitlab_search(domain)))  # type: ignore[no-any-return]


class _BinaryEdgeBackend:
    @staticmethod
    def query(domain: str) -> set[str]:
        return set(run_async_in_sync_context(_fetch_binaryedge_passive(domain)))  # type: ignore[no-any-return]


try:
    register_plugin(
        SUBDOMAIN_ENUMERATOR, "findomain", type="command", args=["findomain", "-t", "{root}", "-q"]
    )(_FindomainBackend.query)
except Exception as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

try:
    register_plugin(SUBDOMAIN_ENUMERATOR, "subdomain_center", contract=SubdomainEnumeratorProtocol)(
        _SubdomainCenterBackend.query
    )
except Exception as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

try:
    register_plugin(SUBDOMAIN_ENUMERATOR, "github_search", contract=SubdomainEnumeratorProtocol)(
        _GitHubSearchBackend.query
    )
except Exception as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

try:
    register_plugin(SUBDOMAIN_ENUMERATOR, "gitlab_search", contract=SubdomainEnumeratorProtocol)(
        _GitLabSearchBackend.query
    )
except Exception as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

try:
    register_plugin(SUBDOMAIN_ENUMERATOR, "binaryedge", contract=SubdomainEnumeratorProtocol)(
        _BinaryEdgeBackend.query
    )
except Exception as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

try:
    from src.recon.sources.virustotal import query_virustotal_passive

    register_plugin(SUBDOMAIN_ENUMERATOR, "virustotal", contract=SubdomainEnumeratorProtocol)(
        query_virustotal_passive
    )
except ImportError as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

try:
    from src.recon.sources.rapiddns import query_rapiddns

    register_plugin(SUBDOMAIN_ENUMERATOR, "rapiddns", contract=SubdomainEnumeratorProtocol)(
        query_rapiddns
    )
except ImportError as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)  # noqa: BLE001

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
    args=["amass", "enum", "-passive", "-norecursive", "-timeout", "10", "-d", "{root}"],
)(None)
register_plugin(
    SUBDOMAIN_ENUMERATOR,
    "shuffledns",
    type="command",
    args=["shuffledns", "-d", "{root}", "-silent"],
)(None)


class _SubdomainPermutatorBackend:
    @staticmethod
    def query(domain: str, known_subdomains: set[str] | None = None) -> set[str]:
        from src.recon.subdomain_permutator import generate_permutations

        if not known_subdomains:
            return set()
        result = generate_permutations(known_subdomains, domain)
        return result.permutations


try:
    register_plugin(SUBDOMAIN_ENUMERATOR, "subdomain_permutator", contract=SubdomainEnumeratorProtocol)(
        _SubdomainPermutatorBackend.query
    )
except Exception as exc:
    logging.warning("Operation failed in subdomains.py: %s", exc, exc_info=True)


def _run_async_provider(provider: Any, root: str) -> Any:
    return run_async_in_sync_context(provider(root))


def enumerate_subdomains(
    scope_entries: list[str], config: Mapping[str, Any], skip_crtsh: bool
) -> set[str]:
    subdomains: set[str] = set()
    command_jobs: list[Any] = []

    tools_config = config.get("tools", {})
    tool_timeout = int(tools_config.get("timeout_seconds", 120))
    tool_retry_policy = build_retry_policy(tools_config)

    raw_roots = sorted(
        {normalize_scope_entry(entry).strip().lower() for entry in scope_entries}, key=len
    )
    roots: list[str] = []
    for r in raw_roots:
        if not r:
            continue
        if any(r.endswith(f".{existing}") for existing in roots):
            continue
        roots.append(r)

    if not roots:
        return set()

    stage_meta: dict[str, Any] = {}
    if isinstance(config, dict):
        raw_meta = config.get("_stage_meta")
        if isinstance(raw_meta, dict):
            stage_meta = raw_meta

    for reg in list_plugins(SUBDOMAIN_ENUMERATOR):
        if reg.key in ("assetfinder", "amass") and not tools_config.get(reg.key, False):
            continue

        if reg.key == "crtsh" and skip_crtsh:
            continue

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
                    logger.debug("Meta wrapper failed for %s/%s", source, root, exc_info=True)
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

    # --- Subdomain permutation (alterx-style) ---
    if tools_config.get("subdomain_permutator", True):
        try:
            from src.recon.subdomain_permutator import generate_permutations

            for root in roots:
                perm_result = generate_permutations(subdomains, root)
                if perm_result.permutations:
                    logger.info(
                        "subdomain_permutator: generated %d candidates for %s",
                        perm_result.permutations_count,
                        root,
                    )
                    subdomains.update(perm_result.permutations)
        except Exception as exc:
            logger.debug("subdomain_permutator failed: %s", exc, exc_info=True)

    return subdomains
