"""Reconnaissance orchestrator.

This module wires the individual recon stages together. It preserves the
original ``run_recon_layer`` contract (returning the historical dict shape)
and adds a number of optional stages that pull in the new modules created
in the recon-critical-analysis work (dnsx wildcard filtering, naabu port
scanning, SPA detection, GraphQL introspection, API-spec discovery, ASN
expansion, favicon fingerprinting, preview-deployment discovery, Shodan /
Censys / LeakIX cross-reference, and focused rescan planning).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from src.core.models import Config
from src.recon.live_hosts import probe_live_hosts
from src.recon.models import ReconCandidate
from src.recon.scoring import infer_target_profile, rank_urls
from src.recon.standardize import standardize_recon_outputs
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import collect_urls, extract_parameters

logger = logging.getLogger(__name__)


def run_recon_layer(
    scope_entries: list[str],
    config: Config,
    *,
    skip_crtsh: bool = False,
) -> dict[str, object]:
    subdomains = enumerate_subdomains(scope_entries, vars(config), skip_crtsh)
    _, live_hosts = probe_live_hosts(subdomains, config)
    urls = collect_urls(live_hosts, scope_entries, config)
    parameters = extract_parameters(urls)
    profile = infer_target_profile(urls)
    ranked_urls = rank_urls(
        urls,
        filters=config.filters,
        scoring=config.scoring,
        mode=config.mode,
        profile=profile,
        history_feedback=None,
    )
    candidates: list[ReconCandidate] = standardize_recon_outputs(
        subdomains=subdomains,
        live_hosts=live_hosts,
        urls=urls,
        ranked_urls=ranked_urls,
        parameters=parameters,
    )
    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "urls": urls,
        "parameters": parameters,
        "ranked_urls": ranked_urls,
        "candidates": candidates,
    }


def _safe_call(label: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Invoke ``fn`` and swallow exceptions, logging them at INFO level.

    Each new recon stage is treated as best-effort — a failure in one
    phase must never abort the rest of the pipeline.  Returns the result
    of ``fn`` on success, or ``None`` on error.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.info("recon stage %s failed: %s", label, exc)
        return None


def _group_subdomains_by_domain(
    subdomains: Iterable[str], scope_entries: Iterable[str]
) -> dict[str, list[str]]:
    """Group candidate subdomains by the most specific matching scope root.

    This is needed because :func:`filter_subdomains_async` operates on one
    root domain at a time. The function returns a ``{domain: [sub...]}``
    mapping keyed by the scope root that each subdomain falls under.
    """
    from src.recon.domain_validation import normalize_domain

    roots = [normalize_domain(s) for s in scope_entries if s and s.strip()]
    roots = sorted({r for r in roots if r}, key=len, reverse=True)
    groups: dict[str, list[str]] = {r: [] for r in roots}
    for sub in subdomains:
        if not sub:
            continue
        clean = sub.strip().lower()
        for root in roots:
            if clean == root or clean.endswith("." + root):
                groups[root].append(clean)
                break
    return groups


def _run_wildcard_filter(
    subdomains: set[str], scope_entries: list[str]
) -> tuple[set[str], dict[str, Any]]:
    """Apply dnsx-style wildcard filtering, returning (kept_hosts, meta)."""
    from src.recon.dnsx_wildcard import (
        filter_subdomains_sync,
        merge_wildcard_results,
    )

    groups = _group_subdomains_by_domain(subdomains, scope_entries)
    results = []
    kept_hosts: set[str] = set()
    for domain, group in groups.items():
        if not domain or not group:
            continue
        try:
            result = filter_subdomains_sync(group, domain)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("wildcard filter failed for %s: %s", domain, exc)
            continue
        results.append(result)
        kept_hosts.update(result.kept_subdomains)
        kept_hosts.add(domain)
    if not results:
        return set(subdomains), {"status": "no-domains"}
    _, ip_map = merge_wildcard_results(results)
    return kept_hosts, {
        "status": "ok",
        "wildcard_domains": [r.domain for r in results if r.has_wildcard],
        "kept_count": len(kept_hosts),
        "ip_map_size": sum(len(v) for v in ip_map.values()),
    }


def _host_strings(live_hosts: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for entry in live_hosts:
        if isinstance(entry, str):
            if entry.strip():
                out.append(entry.strip())
            continue
        if isinstance(entry, dict):
            host = entry.get("host") or entry.get("input") or entry.get("url") or ""
            if host:
                out.append(str(host).strip())
    return out


def _asn_cidrs_for_hosts(hosts: Iterable[str]) -> set[str]:
    cidrs: set[str] = set()
    for host in hosts:
        host = (host or "").strip()
        if not host:
            continue
        try:
            import ipaddress

            ipaddress.ip_address(host)
            cidrs.add(host + "/32")
        except ValueError as exc:
            logger.warning("Operation failed in discovery.py: %s", exc, exc_info=True)  # noqa: BLE001
    return cidrs


def _looks_like_ip(value: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_address(value.strip().lower())
        return True
    except Exception:
        return False


def _reprobe_origin_hosts(
    scope_entries: list[str], progress_callback: Any | None = None
) -> set[str]:
    reprobed_hosts: set[str] = set()
    try:
        from src.recon.origin_discovery import discover_origins_for_findings
    except Exception:  # pragma: no cover - defensive
        return reprobed_hosts
    try:
        findings: list[dict[str, Any]] = []
        for root in scope_entries:
            if not root:
                continue
            findings.append({"domain": root, "source": "scope"})
        if not findings:
            return reprobed_hosts
        result_map = discover_origins_for_findings(
            findings, timeout=6.0, max_domains=len(scope_entries) or 1
        )
        for domain, result in (result_map or {}).items():
            reprobed_hosts.update(result.candidate_hosts)
            reprobed_hosts.update(result.candidate_ips)
            for host in result.candidate_hosts:
                if progress_callback is not None:
                    try:
                        progress_callback(host, ["origin-discovery"])
                    except Exception:  # noqa: BLE001
                        pass
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("origin re-probe failed: %s", exc)
    return reprobed_hosts


def run_spa_aware_headless(
    live_hosts: Iterable[Any],
    progress_callback: Any | None = None,
    spa_page_budget: int = 50,
    spa_depth: int = 4,
) -> tuple[set[str], dict[str, Any]]:
    from src.recon.headless_crawler import headless_crawl_hosts

    hosts = _host_strings(live_hosts)
    if not hosts:
        return set(), {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}
    return headless_crawl_hosts(
        hosts,
        max_pages_per_host=spa_page_budget,
        max_depth=spa_depth,
        progress_callback=progress_callback,
    )


def _run_spa_discovery(
    live_hosts: Iterable[Any], progress_callback: Any | None = None
) -> dict[str, Any]:
    """Run SPA framework detection across live hosts in a bounded thread pool."""
    from concurrent.futures import ThreadPoolExecutor

    from src.recon.spa_detection import (
        collect_recommended_paths,
        probe_framework_endpoints,
        spa_aware_extra_urls,
    )

    hosts = _host_strings(live_hosts)
    if not hosts:
        return {"hits": [], "extra_urls": set()}

    all_hits: list = []
    extra_urls: set[str] = set()
    max_workers = min(8, max(1, len(hosts)))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_framework_endpoints, h): h for h in hosts}
        for fut in futures:
            try:
                hits, _bodies = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("spa probe failed: %s", exc)
                continue
            host = futures[fut]
            all_hits.extend(hits)
            extra_urls.update(spa_aware_extra_urls(host, hits))
            if progress_callback is not None:
                try:
                    progress_callback(host, [h.framework for h in hits])
                except Exception:  # noqa: BLE001
                    pass
    return {
        "hits": [h.framework for h in all_hits],
        "recommended_paths": collect_recommended_paths(all_hits),
        "extra_urls": extra_urls,
    }


def _run_azure_for_scope(
    scope_entries: list[str], progress_callback: Any | None = None
) -> dict[str, Any]:
    """Run Azure Storage recon for each scope root in sequence."""
    from src.recon.azure_sas import AzureReconResult as _AzureReconResult, run_azure_recon_sync

    out: dict[str, Any] = {"results": [], "sas_patterns": 0}
    for entry in scope_entries:
        if not entry:
            continue
        try:
            res = run_azure_recon_sync(entry)
        except Exception as exc:  # noqa: BLE001
            logger.debug("azure recon failed for %s: %s", entry, exc)
            continue
        out["results"].append(
            {
                "target": res.target,
                "web_endpoints": [e.url for e in res.web_endpoints],
                "listing_endpoints": [e.url for e in res.listing_endpoints],
                "sas_pattern_count": len(res.sas_patterns),
            }
        )
        out["sas_patterns"] += len(res.sas_patterns)
        if progress_callback is not None:
            try:
                progress_callback(entry, len(res.web_endpoints))
            except Exception:  # noqa: BLE001
                pass
    return out


def run_enhanced_recon_layer(
    scope_entries: list[str],
    config: Config,
    *,
    skip_crtsh: bool = False,
    progress_callback: Any | None = None,
    run_wildcard_filter: bool = True,
    run_port_scan: bool = True,
    run_spa_detection: bool = True,
    run_graphql_discovery: bool = True,
    run_api_spec_discovery: bool = True,
    run_favicon_fingerprint: bool = True,
    run_asn_expansion: bool = True,
    run_preview_deployments: bool = True,
    run_shodan_censys: bool = True,
    run_alienurl: bool = True,
    run_azure_sas: bool = True,
) -> dict[str, object]:
    """End-to-end recon that layers every P1/P2 enhancement on top of the
    baseline :func:`run_recon_layer` flow.

    The returned dict contains the same keys as :func:`run_recon_layer`
    plus an ``extras`` mapping that holds the results of each optional
    stage.  Each new stage is independently fault-tolerant — a failure
    in one stage never blocks the others.
    """
    subdomains = enumerate_subdomains(scope_entries, vars(config), skip_crtsh)

    wildcard_meta: dict[str, Any] | None = None
    if run_wildcard_filter:
        kept, wildcard_meta = _run_wildcard_filter(subdomains, scope_entries)
        if kept:
            subdomains = set(kept) | {d for d in (scope_entries or []) if d}

    _, live_hosts = probe_live_hosts(subdomains, config, progress_callback=progress_callback)

    extras: dict[str, Any] = {}
    extras.setdefault("origin_reprobe", {})
    reprobed_hosts = (
        _safe_call(
            "origin-reprobe",
            _reprobe_origin_hosts,
            scope_entries,
            progress_callback=progress_callback,
        )
        or set()
    )
    if reprobed_hosts:
        extras["origin_reprobe"] = {
            "hosts": sorted(reprobed_hosts),
            "count": len(reprobed_hosts),
        }
        live_hosts.extend(reprobed_hosts)

    urls = collect_urls(live_hosts, scope_entries, config)
    parameters = extract_parameters(urls)
    profile = infer_target_profile(urls)
    ranked_urls = rank_urls(
        urls,
        filters=config.filters,
        scoring=config.scoring,
        mode=config.mode,
        profile=profile,
        history_feedback=None,
    )

    if run_port_scan:
        from src.recon.port_scanner import run_port_scan_async

        async def _port_scan() -> Any:
            port_hosts: list[str] = _host_strings(live_hosts)
            asn_cidrs: set[str] = set()
            if run_asn_expansion:
                try:
                    asn_cidrs = _asn_cidrs_for_hosts(port_hosts)
                    port_hosts = list(set(port_hosts) | asn_cidrs)
                except Exception:  # noqa: BLE001
                    pass
            for source_hosts in (extras.get("probed_ips"), extras.get("waf_cdn_ips")):
                if isinstance(source_hosts, set) and source_hosts:
                    port_hosts = list(
                        set(port_hosts) | {str(h) for h in source_hosts if str(h).strip()}
                    )
            return await run_port_scan_async(port_hosts)

        extras["port_scan"] = _run_async(_port_scan)

    if run_spa_detection:
        spa_report = _run_spa_discovery(live_hosts, progress_callback)
        extras["spa"] = spa_report
        if bool(config.filters.get("run_headless_on_spa", True)) and spa_report:
            spa_hits = set()
            for hit in (spa_report.get("hits") or []) if isinstance(spa_report, dict) else []:
                if isinstance(hit, dict):
                    host = hit.get("host")
                    if host:
                        spa_hits.add(host)
                elif isinstance(hit, str):
                    spa_hits.add(hit)
            extra_urls = spa_report.get("extra_urls") if isinstance(spa_report, dict) else None
            if isinstance(extra_urls, set):
                spa_hits.update(extra_urls)
            if spa_hits:
                headless_urls, headless_meta = _safe_call(
                    "headless-spa",
                    run_spa_aware_headless,
                    list(spa_hits),
                    progress_callback=progress_callback,
                ) or (set(), {})
                if headless_urls:
                    urls.update(headless_urls)
                    extras["headless_spa"] = headless_meta

    if run_graphql_discovery:
        from src.recon.graphql_introspection import discover_graphql_endpoints

        extras["graphql"] = _safe_call(
            "graphql-introspection",
            discover_graphql_endpoints,
            _host_strings(live_hosts),
        )

    if run_api_spec_discovery:
        from src.recon.api_spec_discovery import discover_api_specs

        extras["api_specs"] = _safe_call(
            "api-spec-discovery",
            discover_api_specs,
            _host_strings(live_hosts),
        )

    if run_favicon_fingerprint:
        from src.recon.favicon_fingerprint import fetch_favicons

        extras["favicons"] = _safe_call(
            "favicon-fingerprint",
            fetch_favicons,
            _host_strings(live_hosts),
            progress_callback=progress_callback,
        )

    if run_asn_expansion:
        from src.recon.asn_expansion import asn_for_url, expand_ips_to_cidrs

        ip_set: set[str] = set()
        for host in _host_strings(live_hosts):
            if host and host.replace(".", "").isdigit():
                ip_set.add(host)
        hosts_for_asn = _host_strings(live_hosts)[:32]
        asn_records = [asn_for_url(h) for h in hosts_for_asn]
        extras["asn"] = {
            "ip_count": len(ip_set),
            "cidrs": expand_ips_to_cidrs(ip_set) if ip_set else [],
            "records": [r for r in asn_records if r is not None],
        }

    if run_preview_deployments:
        from src.recon.preview_deployments import discover_preview_deployments

        extras["preview"] = _safe_call(
            "preview-deployments",
            discover_preview_deployments,
            _host_strings(live_hosts),
            progress_callback=progress_callback,
        )

    if run_shodan_censys:
        from src.recon.shodan_censys import cross_reference_ips

        ips: list[str] = []
        for host in _host_strings(live_hosts):
            if host and host.replace(".", "").isdigit():
                ips.append(host)
        extras["shodan_censys"] = _safe_call(
            "shodan-censys",
            cross_reference_ips,
            ips[:64],
        )

    if run_alienurl:
        from src.recon.alienurl import run_aggregated_archive

        extras["archive_aggregated"] = _safe_call(
            "alienurl-aggregator",
            run_aggregated_archive,
            _host_strings(live_hosts),
            progress_callback=progress_callback,
        )

    if getattr(config, "run_waf_cdn_detection", False):
        from src.recon.waf_cdn_detector import build_waf_cdn_report, detect_waf_cdn

        waf_findings = (
            _safe_call(
                "waf-cdn-detection",
                detect_waf_cdn,
                _host_strings(live_hosts),
                max_urls=int(config.filters.get("waf_max_urls", 50) or 50),
            )
            or []
        )
        waf_ips: set[str] = set()
        waf_hosts: set[str] = set()
        for finding in waf_findings:
            url = finding.get("url") or finding.get("input")
            host = None
            if isinstance(url, str) and "://" in url:
                host = url.split("://", 1)[1].split("/", 1)[0]
            if not host:
                host = finding.get("host")
            if host:
                waf_hosts.add(host)
            if host and _looks_like_ip(host):
                waf_ips.add(host)
        if waf_hosts or waf_ips:
            try:
                _, waf_live_hosts = probe_live_hosts(
                    list(waf_hosts | waf_ips), config, progress_callback=progress_callback
                )
                live_hosts.extend(waf_live_hosts)
            except Exception:  # noqa: BLE001
                pass
        report = _safe_call(
            "waf-cdn-report",
            build_waf_cdn_report,
            waf_findings,
        )
        extras["waf_cdn"] = report if isinstance(report, dict) else {}

    if run_azure_sas:
        extras["azure"] = _run_azure_for_scope(scope_entries, progress_callback)

    candidates: list[ReconCandidate] = standardize_recon_outputs(
        subdomains=subdomains,
        live_hosts=live_hosts,
        urls=urls,
        ranked_urls=ranked_urls,
        parameters=parameters,
    )

    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "urls": urls,
        "parameters": parameters,
        "ranked_urls": ranked_urls,
        "candidates": candidates,
        "wildcard_filter": wildcard_meta,
        "extras": extras,
    }


def _run_async(coro_factory: Any) -> Any:
    """Run an async coroutine factory from sync code, swallowing errors.

    ``coro_factory`` is a zero-arg callable that returns a coroutine.
    This wrapper handles the "no running event loop" case and never
    raises.
    """
    import asyncio

    try:
        coro = coro_factory()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(lambda: asyncio.run(coro)).result()
        return asyncio.run(coro)
    except Exception as exc:  # pragma: no cover - defensive
        logger.info("async stage failed: %s", exc)
        return None


def build_focused_rescan_plan(
    *,
    drift_report: dict[str, Any] | None = None,
    previous_run_meta: dict[str, Any] | None = None,
    small_drift_threshold: float = 0.05,
    large_drift_threshold: float = 0.20,
) -> dict[str, Any]:
    """Convenience wrapper around :mod:`src.recon.focused_rescan`.

    Returns an empty plan if either argument is missing — callers should
    treat empty plans as "no rescan needed".
    """
    from src.recon.focused_rescan import build_focused_rescan_plan as _build

    if drift_report is None:
        return {"rescan": False, "reason": "no drift report"}
    try:
        return _build(
            drift_report=drift_report,
            previous_run_meta=previous_run_meta,
            small_drift_threshold=small_drift_threshold,
            large_drift_threshold=large_drift_threshold,
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.info("focused rescan plan failed: %s", exc)
        return {"rescan": False, "reason": f"planner error: {exc}"}
