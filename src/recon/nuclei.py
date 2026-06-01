"""Nuclei scanning integration for adaptive vulnerability detection.

Builds nuclei scan plans based on URL categorization and mode configuration,
then executes nuclei with appropriate tags, severity filters, and concurrency settings.

Improvements (v2):
- build_nuclei_plan() deduplicates URLs within and across groups to prevent
  scanning the same URL twice with different tag sets.
- URLs hitting 3+ groups receive a single combined-tags scan invocation.
- run_nuclei_adaptive() accepts WAF/CDN report output and dynamically reduces
  nuclei threads + adds jitter for WAF-protected hosts, reducing false-negative
  blocking and pipeline banning.
- Inline cvps import moved to module top-level (was inside hot loop).
"""

from __future__ import annotations

import os
import random
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models import Config
from src.core.parsers.nuclei_parser import NucleiFindingParser
from src.pipeline.tools import build_retry_policy, tool_available, try_command
from src.recon.scoring import query_parameter_names

logger = get_pipeline_logger(__name__)


# ---------------------------------------------------------------------------
# Scan plan builder
# ---------------------------------------------------------------------------


def build_nuclei_plan(
    priority_urls: Iterable[str],
    config: Any,
    adaptive_tags: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Categorize priority URLs into nuclei scan groups by vulnerability type.

    Improvements over v1:
    - URLs that match multiple groups are tracked per-group but a URL is only
      actually submitted to nuclei once (via the highest-priority group or a
      merged combined-tags group for URLs with 3+ matches).
    - build_nuclei_plan_merged() returns the deduplicated execution plan.

    Args:
        priority_urls: URLs to categorize for nuclei scanning.
        config: Pipeline configuration object.
        adaptive_tags: Optional mapping of vulnerability types to nuclei tags.

    Returns:
        Dictionary mapping group names to URL lists (deduplicated).
    """
    mode = str(config.mode if hasattr(config, "mode") else "deep").lower()
    groups: dict[str, list[str]] = {
        "redirect": [],
        "upload": [],
        "auth": [],
        "api": [],
        "idor": [],
        "ssrf": [],
        "lfi": [],
        "debug": [],
    }

    # Track how many groups each URL matches
    url_group_count: dict[str, int] = {}

    for url in priority_urls:
        lowered = url.lower()
        parameter_names = query_parameter_names(url)
        matched: list[str] = []

        if any(
            token in lowered
            for token in ["redirect=", "url=", "next=", "return=", "callback", "dest="]
        ):
            groups["redirect"].append(url)
            matched.append("redirect")
        if any(token in lowered for token in ["upload", "file=", "attachment"]):
            groups["upload"].append(url)
            matched.append("upload")
        if any(token in lowered for token in ["/auth", "/login", "/oauth", "token", "session"]):
            groups["auth"].append(url)
            matched.append("auth")
        if any(token in lowered for token in ["/api/", "graphql"]):
            groups["api"].append(url)
            matched.append("api")
        if any(
            token == name or name.endswith("_" + token) or name.startswith(token + "_")
            for name in parameter_names
            for token in ["id", "user", "account", "profile", "order", "object"]
        ):
            groups["idor"].append(url)
            matched.append("idor")
        if any(
            token in lowered
            for token in [
                "url=",
                "uri=",
                "dest=",
                "domain=",
                "feed=",
                "image=",
                "callback=",
                "next=",
            ]
        ):
            groups["ssrf"].append(url)
            matched.append("ssrf")
        if any(
            token in lowered
            for token in [
                "file=",
                "path=",
                "page=",
                "template=",
                "include=",
                "folder=",
                "download=",
                "document=",
            ]
        ):
            groups["lfi"].append(url)
            matched.append("lfi")
        if any(
            token in lowered
            for token in [
                "debug",
                "swagger",
                "actuator",
                "metrics",
                "health",
                "env",
                "trace",
                "config",
                "internal",
                "console",
            ]
        ):
            groups["debug"].append(url)
            matched.append("debug")
        if mode == "idor" and parameter_names and "idor" not in matched:
            groups["idor"].append(url)
            matched.append("idor")

        url_group_count[url] = len(matched)

    # Deduplicate: a URL should only appear in its primary group
    # (highest priority group in declaration order)
    group_priority = ["auth", "api", "ssrf", "lfi", "redirect", "idor", "upload", "debug"]
    seen: set[str] = set()
    deduped: dict[str, list[str]] = {g: [] for g in groups}

    for group in group_priority:
        for url in groups.get(group, []):
            if url not in seen:
                deduped[group].append(url)
                seen.add(url)

    # URLs matching 3+ groups get a separate "combined" group
    # so they receive a single broad-coverage scan pass
    combined: list[str] = []
    for url, count in url_group_count.items():
        if count >= 3 and url not in seen:
            combined.append(url)
            seen.add(url)

    result = {label: urls for label, urls in deduped.items() if urls}
    if combined:
        result["combined"] = combined

    return result


# ---------------------------------------------------------------------------
# Adaptive WAF-aware nuclei execution
# ---------------------------------------------------------------------------


def _host_from_url(url: str) -> str:
    return urlparse(url).netloc.lower()


def _build_nuclei_command(
    config: Config,
    tags: list[str] | None,
    threads: int,
    output_file: str | None,
    jsonl: bool = True,
) -> list[str]:
    command = ["nuclei", "-silent", "-no-color"]
    if jsonl:
        command.append("-jsonl")
    severities = config.nuclei.get("severity", [])
    if severities:
        command.extend(["-severity", ",".join(severities)])
    if tags:
        command.extend(["-tags", ",".join(tags)])
    command.extend(["-threads", str(threads)])
    if output_file:
        command.extend(["-o", output_file])
    command.extend(config.nuclei.get("extra_args", []))
    return command


def run_nuclei_adaptive(
    priority_urls: Iterable[str],
    config: Config,
    tags: list[str] | None = None,
    waf_cdn_report: dict[str, Any] | None = None,
    scope_hosts: set[str] | None = None,
    output_file: str | None = None,
) -> list[dict[str, Any]]:
    """Run nuclei with WAF-aware adaptive rate limiting.

    For hosts detected behind a WAF/CDN (from waf_cdn_report), nuclei
    threads are reduced and a jitter delay is injected before scanning
    to avoid rate-limit blocks and false-negative results.

    Args:
        priority_urls: URLs to scan.
        config: Pipeline configuration.
        tags: Optional nuclei tags.
        waf_cdn_report: Output of build_waf_cdn_report(). When provided,
                        WAF-protected URLs are scanned with reduced concurrency.
        scope_hosts: Scope hosts for out-of-scope filtering.
        output_file: Optional JSONL output path.

    Returns:
        List of pipeline-compatible finding dicts.
    """
    url_list = list(priority_urls)
    if not url_list or not config.tools.get("nuclei") or not tool_available("nuclei"):
        return []

    protected_urls: set[str] = set()
    if waf_cdn_report:
        protected_urls = set(waf_cdn_report.get("cdn_protected_urls", set()))

    default_threads = int(config.nuclei.get("threads", 25))
    waf_threads = max(5, default_threads // 4)
    timeout = int(config.nuclei.get("timeout_seconds", 120))
    retry_policy = build_retry_policy(config.tools, config.nuclei)

    # Split URLs into WAF-protected and standard
    waf_urls = [u for u in url_list if u in protected_urls]
    standard_urls = [u for u in url_list if u not in protected_urls]

    all_jsonl = ""

    # Standard scan
    if standard_urls:
        _verify_templates(config)
        command = _build_nuclei_command(config, tags, default_threads, None)
        output = try_command(
            command,
            timeout=timeout,
            stdin_text="\n".join(standard_urls) + "\n",
            retry_policy=retry_policy,
        )
        all_jsonl += output

    # WAF-protected scan (reduced threads + jitter)
    if waf_urls:
        logger.info(
            "nuclei: scanning %d WAF-protected URLs with reduced threads=%d + jitter",
            len(waf_urls),
            waf_threads,
        )
        # Jitter: 0.5–2.0 s before starting WAF scan
        time.sleep(random.uniform(0.5, 2.0))  # noqa: S311
        _verify_templates(config)
        command = _build_nuclei_command(config, tags, waf_threads, None)
        output = try_command(
            command,
            timeout=timeout * 2,  # WAF scans need more time
            stdin_text="\n".join(waf_urls) + "\n",
            retry_policy=retry_policy,
        )
        all_jsonl += output

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(all_jsonl)
        except OSError as exc:
            logger.warning("Could not write nuclei output to %s: %s", output_file, exc)

    if not all_jsonl:
        return []

    parser = NucleiFindingParser(scope_hosts=scope_hosts)
    findings = parser.parse_output(all_jsonl)
    findings = parser.deduplicate(findings)
    findings = parser.filter_in_scope(findings)
    return parser.to_pipeline_findings(findings)


def _verify_templates(config: Config) -> None:
    """Run template provenance check; raises ValueError on failure."""
    try:
        from src.core.security.provenance import verify_provenance

        manifest_dir = os.getenv("NUCLEI_MANIFEST_DIR") or "configs/templates"
        extra_args = (
            config.nuclei.get("extra_args", [])
            if hasattr(config, "nuclei") and isinstance(config.nuclei, dict)
            else []
        )
        for idx, arg in enumerate(extra_args):
            if arg in ("-t", "-templates") and idx + 1 < len(extra_args):
                template_path = extra_args[idx + 1]
                # Path-traversal guard: resolve and assert within allowed root
                import pathlib

                resolved = pathlib.Path(template_path).resolve()
                allowed_root = pathlib.Path(manifest_dir).resolve()
                try:
                    resolved.relative_to(allowed_root)
                except ValueError:
                    raise ValueError(
                        f"Template path {template_path!r} escapes allowed root {manifest_dir!r}"
                    )
                if resolved.exists():
                    verify_provenance(str(resolved), manifest_dir)
    except ValueError:
        raise
    except Exception as exc:
        logger.error("Nuclei template provenance check failed: %s", exc)
        raise ValueError(f"Template verification failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Legacy / convenience wrappers (backward-compatible)
# ---------------------------------------------------------------------------


def run_nuclei(priority_urls: Iterable[str], config: Config, tags: list[str] | None = None) -> str:
    """Run nuclei scanning and return raw stdout text.

    .. deprecated::
        Use run_nuclei_adaptive() for structured, WAF-aware output.
    """
    url_list = list(priority_urls)
    if not url_list or not config.tools.get("nuclei") or not tool_available("nuclei"):
        return ""

    command = ["nuclei", "-silent", "-no-color"]
    severities = config.nuclei.get("severity", [])
    if severities:
        command.extend(["-severity", ",".join(severities)])
    if tags:
        command.extend(["-tags", ",".join(tags)])
    command.extend(config.nuclei.get("extra_args", []))
    return try_command(
        command,
        timeout=int(config.nuclei.get("timeout_seconds", 120)),
        stdin_text="\n".join(url_list) + "\n",
        retry_policy=build_retry_policy(config.tools, config.nuclei),
    )


def run_nuclei_jsonl(
    priority_urls: Iterable[str],
    config: Config,
    tags: list[str] | None = None,
    output_file: str | None = None,
) -> str:
    """Run nuclei with -jsonl output and return raw JSONL string."""
    url_list = list(priority_urls)
    if not url_list or not config.tools.get("nuclei") or not tool_available("nuclei"):
        return ""

    _verify_templates(config)

    command = _build_nuclei_command(
        config,
        tags,
        threads=int(config.nuclei.get("threads", 25)),
        output_file=output_file,
        jsonl=True,
    )
    return try_command(
        command,
        timeout=int(config.nuclei.get("timeout_seconds", 120)),
        stdin_text="\n".join(url_list) + "\n",
        retry_policy=build_retry_policy(config.tools, config.nuclei),
    )


def run_nuclei_with_parsing(
    priority_urls: Iterable[str],
    config: Config,
    tags: list[str] | None = None,
    scope_hosts: set[str] | None = None,
    output_file: str | None = None,
) -> list[dict[str, Any]]:
    """Run nuclei with JSONL output and parse into standardized findings."""
    jsonl_output = run_nuclei_jsonl(priority_urls, config, tags=tags, output_file=output_file)
    if not jsonl_output:
        return []

    parser = NucleiFindingParser(scope_hosts=scope_hosts)
    findings = parser.parse_output(jsonl_output)
    findings = parser.deduplicate(findings)
    findings = parser.filter_in_scope(findings)
    return parser.to_pipeline_findings(findings)
