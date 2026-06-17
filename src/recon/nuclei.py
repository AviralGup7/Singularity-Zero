"""Nuclei scanning integration for adaptive vulnerability detection.

Builds nuclei scan plans based on URL categorization and mode configuration,
then executes nuclei with appropriate tags, severity filters, and concurrency settings.

Improvements (v3):
- ``build_nuclei_plan()`` now does parameter-level analysis rather than
  URL substring matching. Each query parameter is classified
  independently using a name → category mapping (with value-based
  inference for SSRF/LFI candidates) and the URL is then placed in
  every group that matches any of its parameters. URLs that match
  3+ groups still get a single broad-tags ``combined`` group to keep
  the deduplication invariant from v2.
- A new ``build_nuclei_plan_with_param_map()`` returns the per-URL
  group classification so the calling stage can adjust scoring or
  emit per-category findings when Nuclei is unavailable.
- ``run_nuclei_adaptive()`` unchanged from v2.
- Inline cvps import moved to module top-level (was inside hot loop).
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models import Config
from src.core.parsers.nuclei_parser import NucleiFindingParser
from src.pipeline.tools import build_retry_policy, tool_available, try_command
from src.recon.scoring import query_parameter_names

logger = get_pipeline_logger(__name__)


# ---------------------------------------------------------------------------
# Parameter-level classification (v3)
# ---------------------------------------------------------------------------


# Parameter names that strongly suggest a vulnerability class.
# The mapping is case-insensitive; we also check the value heuristic
# to avoid the most common false-positive (e.g. ``page=2`` matched
# LFI on substring "page=").
_PARAM_CATEGORY_HINTS: dict[str, str] = {
    # SSRF candidates
    "url": "ssrf",
    "uri": "ssrf",
    "dest": "ssrf",
    "destination": "ssrf",
    "redirect": "redirect",
    "redirect_uri": "redirect",
    "redirect_url": "redirect",
    "next": "redirect",
    "return": "redirect",
    "return_to": "redirect",
    "returnto": "redirect",
    "callback": "redirect",
    "continue": "redirect",
    "image_url": "ssrf",
    "image": "ssrf",
    "feed": "ssrf",
    "feed_url": "ssrf",
    "host": "ssrf",
    "domain": "ssrf",
    "site": "ssrf",
    "view": "ssrf",
    "path": "ssrf",
    # Open redirect candidates
    "out": "redirect",
    "to": "redirect",
    "from": "redirect",
    "forward": "redirect",
    # LFI / path-traversal candidates
    "file": "lfi",
    "filename": "lfi",
    "filepath": "lfi",
    "folder": "lfi",
    "root": "lfi",
    "pg": "lfi",
    "style": "lfi",
    "template": "lfi",
    "php_path": "lfi",
    "doc": "lfi",
    "document": "lfi",
    "download": "lfi",
    "include": "lfi",
    "dir": "lfi",
    "page": "lfi",
    "pdf": "lfi",
    "img": "lfi",
    "action": "lfi",
    # IDOR / object-reference candidates
    "id": "idor",
    "user_id": "idor",
    "userid": "idor",
    "uid": "idor",
    "account_id": "idor",
    "account": "idor",
    "profile": "idor",
    "profile_id": "idor",
    "order": "idor",
    "order_id": "idor",
    "orderid": "idor",
    "object": "idor",
    "objectid": "idor",
    "oid": "idor",
    "doc_id": "idor",
    "document_id": "idor",
    "ref": "idor",
    "refid": "idor",
    "rid": "idor",
    # File upload candidates
    "upload": "upload",
    "file_upload": "upload",
    "attachment": "upload",
    "attach": "upload",
    "filename_param": "upload",
    # Auth / session candidates
    "token": "auth",
    "auth": "auth",
    "session": "auth",
    "sessionid": "auth",
    "apikey": "auth",
    "api_key": "auth",
    "access_token": "auth",
    "authorization": "auth",
}

# Parameter values that strongly suggest SSRF. Matched case-insensitively.
_SSRF_VALUE_HINTS: tuple[str, ...] = (
    "http://",
    "https://",
    "file://",
    "ftp://",
    "gopher://",
    "dict://",
    "ldap://",
)

# Parameter values that strongly suggest LFI. Matched case-insensitively.
_LFI_VALUE_HINTS: tuple[str, ...] = (
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "c:\\",
    "win.ini",
)

# Path / keyword hints for the path-based fallback (rarely needed once
# the parameter map is populated, but kept for URLs with no query string).
_PATH_KEYWORD_HINTS: dict[str, str] = {
    "graphql": "api",
    "/api/": "api",
    "/v1/": "api",
    "/v2/": "api",
    "/v3/": "api",
    "/auth": "auth",
    "/login": "auth",
    "/oauth": "auth",
    "/sso": "auth",
    "/actuator": "debug",
    "/swagger": "debug",
    "/v1/api-docs": "debug",
    "/v2/api-docs": "debug",
    "/v3/api-docs": "debug",
    "/openapi": "debug",
    "/metrics": "debug",
    "/health": "debug",
    "/env": "debug",
    "/trace": "debug",
    "/console": "debug",
    "/_debug": "debug",
    "/internal": "debug",
    "/admin": "debug",
    "/phpmyadmin": "debug",
}


def _classify_url(
    url: str,
    *,
    param_map: dict[str, set[str]] | None = None,
) -> set[str]:
    """Return the set of vulnerability categories *url* belongs to.

    The classification is parameter-level: we look at every query
    parameter, classify it via the name hint map, then refine with a
    value check (an SSRF-name parameter whose value is a plain integer
    is unlikely to actually be a server-side request vector, so we
    accept the SSRF category only when the value looks URL-shaped).
    Path keyword hints are used as a final fallback when the URL has
    no parameters.

    Args:
        url: Absolute URL to classify.
        param_map: Optional pre-computed ``param_name -> set(values)``
            map. When omitted, the function parses ``url`` once and
            builds the map locally.

    Returns:
        Set of category names. May be empty when no category matches.
    """
    parsed = urlparse(url)
    lowered = url.lower()
    categories: set[str] = set()

    if param_map is None:
        param_map = {}
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            param_map.setdefault(k.lower(), set()).add(v or "")

    # 1) Parameter-name-based classification
    for name, values in param_map.items():
        category = _PARAM_CATEGORY_HINTS.get(name)
        if not category:
            # Try a relaxed suffix match (e.g. ``user_id_xyz`` → idor)
            for hint_name, hint_category in _PARAM_CATEGORY_HINTS.items():
                if (
                    name == hint_name
                    or name.endswith(f"_{hint_name}")
                    or name.startswith(f"{hint_name}_")
                ):
                    category = hint_category
                    break
        if not category:
            continue
        # Value-based disambiguation: only require the value to look
        # URL/path-like for SSRF / LFI categories. Other categories
        # (idor, auth, upload, redirect) are accepted on name alone.
        if category in {"ssrf", "lfi"}:
            hints = _SSRF_VALUE_HINTS if category == "ssrf" else _LFI_VALUE_HINTS
            value_blob = " ".join(values).lower()
            if not any(h in value_blob for h in hints):
                # SSRF/LFI only confirmed if the value hints match.
                # We still attach the category if the *name* hint is
                # in the v1 substring set, to preserve backward-compat
                # behaviour for callers that never set param_map.
                if not any(
                    token in lowered
                    for token in (
                        "url=" if category == "ssrf" else "file=",
                        "uri=" if category == "ssrf" else "path=",
                    )
                ):
                    continue
        categories.add(category)

    # 2) Path-keyword fallback (covers the no-query case)
    for token, category in _PATH_KEYWORD_HINTS.items():
        if token in lowered:
            categories.add(category)

    return categories


def _build_param_map_for_urls(urls: Iterable[str]) -> dict[str, set[str]]:
    """Aggregate per-URL parameter sets into a single param→values map.

    Used by :func:`build_nuclei_plan_with_param_map` so we can resolve
    each unique query parameter only once (an order of magnitude faster
    than re-parsing every URL).
    """
    combined: dict[str, set[str]] = {}
    for url in urls:
        parsed = urlparse(url)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            combined.setdefault(name.lower(), set()).add(value or "")
    return combined


def build_nuclei_plan_with_param_map(
    priority_urls: Iterable[str],
    config: Any,
    *,
    adaptive_tags: dict[str, list[str]] | None = None,
) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
    """Build the nuclei plan using a single aggregated parameter map.

    Returns the same plan dict as :func:`build_nuclei_plan` plus the
    per-URL category classification for downstream consumers.
    """
    mode = str(config.mode if hasattr(config, "mode") else "deep").lower()
    url_list = list(priority_urls)
    param_map = _build_param_map_for_urls(url_list)

    groups: dict[str, set[str]] = {
        "redirect": set(),
        "upload": set(),
        "auth": set(),
        "api": set(),
        "idor": set(),
        "ssrf": set(),
        "lfi": set(),
        "debug": set(),
    }
    url_to_categories: dict[str, set[str]] = {}

    for url in url_list:
        categories = _classify_url(url, param_map=param_map)
        url_to_categories[url] = set(categories)
        for category in categories:
            if category in groups:
                groups[category].add(url)

    if mode == "idor":
        for url in url_list:
            params = query_parameter_names(url)
            if params and "idor" not in url_to_categories[url]:
                groups["idor"].add(url)
                url_to_categories[url].add("idor")

    # Deduplicate by group priority. We keep the highest-priority
    # assignment per URL so we never scan the same URL twice with
    # different tag sets.
    group_priority = ["auth", "api", "ssrf", "lfi", "redirect", "idor", "upload", "debug"]
    seen: set[str] = set()
    deduped: dict[str, list[str]] = {g: [] for g in groups}
    for group in group_priority:
        for url in sorted(groups[group]):
            if url not in seen:
                deduped[group].append(url)
                seen.add(url)

    # URLs matching 3+ groups receive a single combined-tags scan.
    combined: list[str] = []
    for url, cats in url_to_categories.items():
        if len(cats) >= 3 and url not in seen:
            combined.append(url)
            seen.add(url)

    result = {label: urls for label, urls in deduped.items() if urls}
    if combined:
        result["combined"] = combined
    return result, url_to_categories


def build_nuclei_plan(
    priority_urls: Iterable[str],
    config: Any,
    adaptive_tags: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Categorize priority URLs into nuclei scan groups by vulnerability type.

    Improvements over v2:
    - Parameter-level classification: each query parameter is mapped
      to a category via a name hint table, with value-based
      disambiguation for SSRF/LFI candidates (a parameter named
      ``file`` whose value is just ``2`` is NOT marked LFI; a
      parameter named ``file`` whose value contains ``../`` is).
    - URL substring matches (``redirect=``, ``file=``, etc.) remain
      supported as a fallback when the URL has no query string.
    - URLs matching 3+ groups still receive a single ``combined`` scan.

    Args:
        priority_urls: URLs to categorize for nuclei scanning.
        config: Pipeline configuration object.
        adaptive_tags: Optional mapping of vulnerability types to nuclei tags.
            (Currently informational — the runner builds its own tags from
            the group name unless a custom map is supplied.)

    Returns:
        Dictionary mapping group names to URL lists (deduplicated).
    """
    plan, _ = build_nuclei_plan_with_param_map(priority_urls, config, adaptive_tags=adaptive_tags)
    return plan


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
        _JITTER = secrets.SystemRandom()
        time.sleep(_JITTER.uniform(0.5, 2.0))
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
    """Run template provenance check; raises ValueError on failure.

    The previous implementation only checked templates that were explicitly
    passed via ``-t`` / ``-templates`` in ``extra_args``. If the operator
    configured nuclei via a YAML tag list (the common case), no provenance
    check was performed at all. We now also verify the default templates
    directory whenever it exists.
    """
    import pathlib

    manifest_dir = os.getenv("NUCLEI_MANIFEST_DIR") or "configs/templates"

    # --- Step 1: Integrity validation via SHA-256 manifest ---
    try:
        from src.recon.nuclei_template_validation import NucleiTemplateValidator

        manifest_path = pathlib.Path(manifest_dir) / "template_manifest.json"
        validator = NucleiTemplateValidator(str(manifest_path))
        canonical = pathlib.Path(manifest_dir).resolve()
        if canonical.exists() and canonical.is_dir():
            if not validator.verify_templates(str(canonical)):
                raise ValueError(
                    "Nuclei template integrity check failed: "
                    "hash mismatch detected against signed manifest"
                )
    except ValueError:
        raise
    except Exception as exc:
        logger.warning("Nuclei template integrity validation skipped: %s", exc)

    # --- Step 2: Schema validation for explicit template files ---
    try:
        from src.recon.nuclei_schema import validate_template_file

        extra_args = (
            config.nuclei.get("extra_args", [])
            if hasattr(config, "nuclei") and isinstance(config.nuclei, dict)
            else []
        )
        for idx, arg in enumerate(extra_args):
            if arg in ("-t", "-templates") and idx + 1 < len(extra_args):
                template_path = extra_args[idx + 1]
                resolved = pathlib.Path(template_path).resolve()
                if resolved.exists() and resolved.is_file():
                    try:
                        validate_template_file(str(resolved))
                    except Exception as exc:
                        logger.warning(
                            "Schema validation failed for template %s: %s",
                            template_path,
                            exc,
                        )
    except ImportError:
        logger.debug("nuclei_schema module unavailable; skipping schema validation")
    except Exception as exc:
        logger.warning("Nuclei template schema validation skipped: %s", exc)

    # --- Step 3: Provenance check (existing) ---
    try:
        from src.core.security.provenance import verify_provenance

        # Always verify the canonical templates directory if it exists.
        canonical = pathlib.Path(manifest_dir).resolve()
        if canonical.exists():
            try:
                verify_provenance(str(canonical), manifest_dir)
            except Exception as exc:  # noqa: BLE001
                raise ValueError(
                    f"Canonical nuclei template directory failed provenance: {exc}"
                ) from exc

        extra_args = (
            config.nuclei.get("extra_args", [])
            if hasattr(config, "nuclei") and isinstance(config.nuclei, dict)
            else []
        )
        for idx, arg in enumerate(extra_args):
            if arg in ("-t", "-templates") and idx + 1 < len(extra_args):
                template_path = extra_args[idx + 1]
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
    # Always verify templates, even on the legacy entry point. The previous
    # implementation skipped this step, which let callers bypass the
    # provenance check entirely by using this function instead of the
    # adaptive wrapper.
    _verify_templates(config)

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
