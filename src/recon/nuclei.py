"""Nuclei scanning integration for adaptive vulnerability detection.

Builds nuclei scan plans based on URL categorization and mode configuration,
then executes nuclei with appropriate tags, severity filters, and concurrency settings.
"""

from collections.abc import Iterable
from typing import Any

from src.core.models import Config
from src.core.parsers.nuclei_parser import NucleiFindingParser
from src.pipeline.tools import build_retry_policy, tool_available, try_command
from src.recon.scoring import query_parameter_names


def build_nuclei_plan(
    priority_urls: Iterable[str],
    config: Any,
    adaptive_tags: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Categorize priority URLs into nuclei scan groups by vulnerability type.

    Args:
        priority_urls: URLs to categorize for nuclei scanning.
        config: Pipeline configuration object.
        adaptive_tags: Optional mapping of vulnerability types to nuclei tags.

    Returns:
        Dictionary mapping group names to URL lists.
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
    for url in priority_urls:
        lowered = url.lower()
        parameter_names = query_parameter_names(url)
        if any(
            token in lowered
            for token in ["redirect=", "url=", "next=", "return=", "callback", "dest="]
        ):
            groups["redirect"].append(url)
        if any(token in lowered for token in ["upload", "file=", "attachment"]):
            groups["upload"].append(url)
        if any(token in lowered for token in ["/auth", "/login", "/oauth", "token", "session"]):
            groups["auth"].append(url)
        if any(token in lowered for token in ["/api/", "graphql"]):
            groups["api"].append(url)
        if any(
            token == name or name.endswith("_" + token) or name.startswith(token + "_")
            for name in parameter_names
            for token in ["id", "user", "account", "profile", "order", "object"]
        ):
            groups["idor"].append(url)
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
        if mode == "idor" and parameter_names and url not in groups["idor"]:
            groups["idor"].append(url)
    return {label: urls for label, urls in groups.items() if urls}


def run_nuclei(priority_urls: Iterable[str], config: Config, tags: list[str] | None = None) -> str:
    """Run nuclei scanning and return raw stdout text.

    .. deprecated::
        Use :func:`run_nuclei_with_parsing` for structured finding output
        or :func:`run_nuclei_jsonl` for raw JSONL output.
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
    """Run nuclei with -jsonl output and return raw JSONL string.

    Args:
        priority_urls: URLs to scan.
        config: Pipeline configuration.
        tags: Optional nuclei tags.
        output_file: Optional file path to write JSONL output.

    Returns:
        Raw JSONL output string from nuclei.
    """
    url_list = list(priority_urls)
    if not url_list or not config.tools.get("nuclei") or not tool_available("nuclei"):
        return ""

    command = ["nuclei", "-silent", "-no-color", "-jsonl"]
    severities = config.nuclei.get("severity", [])
    if severities:
        command.extend(["-severity", ",".join(severities)])
    if tags:
        command.extend(["-tags", ",".join(tags)])
    if output_file:
        command.extend(["-o", output_file])
    command.extend(config.nuclei.get("extra_args", []))
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
    """Run nuclei with JSONL output and parse into standardized findings.

    Args:
        priority_urls: URLs to scan.
        config: Pipeline configuration.
        tags: Optional nuclei tags.
        scope_hosts: Scope hosts for filtering out-of-scope findings.
        output_file: Optional file path for JSONL output persistence.

    Returns:
        List of pipeline-compatible finding dicts parsed from nuclei output.
    """
    jsonl_output = run_nuclei_jsonl(priority_urls, config, tags=tags, output_file=output_file)
    if not jsonl_output:
        return []

    parser = NucleiFindingParser(scope_hosts=scope_hosts)
    findings = parser.parse_output(jsonl_output)
    findings = parser.deduplicate(findings)
    findings = parser.filter_in_scope(findings)
    return parser.to_pipeline_findings(findings)
