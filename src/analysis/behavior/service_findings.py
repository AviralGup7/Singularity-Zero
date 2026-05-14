"""Service analysis findings builder for fingerprinting and exposure detection.

Processes live service records to build findings for service fingerprinting,
default credential hints, exposed services, TLS misconfigurations, admin
panel detection, and development environment identification.
"""

import logging
import time
from datetime import UTC, datetime
from typing import Any

from src.analysis.behavior.service_runtime import (
    ADMIN_PATHS,
    fetch_http_details,
    normalize_title,
    record_host,
    record_port,
    service_url,
)
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

logger = logging.getLogger(__name__)


SERVICE_SIGNATURES = {
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "kibana": ("kibana", "kibana"),
    "elasticsearch": ("elasticsearch", "elastic"),
    "prometheus": ("prometheus", "prometheus"),
    "rabbitmq": ("rabbitmq", "rabbitmq"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "sonarqube": ("sonarqube", "sonarqube"),
    "gitlab": ("gitlab", "gitlab"),
    "adminer": ("adminer", "adminer"),
    "argocd": ("argocd", "argo-cd"),
    "consul": ("consul", "hashicorp-consul"),
    "vault": ("vault", "hashicorp-vault"),
    "nexus": ("nexus", "sonatype-nexus"),
    "jfrog": ("jfrog", "artifactory"),
    "minio": ("minio", "minio-console"),
    "portainer": ("portainer", "portainer.io"),
    "kubernetes_dashboard": ("kubernetes-dashboard", "kubernetes dashboard"),
    "jupyter": ("jupyter", "jupyterlab"),
    "airflow": ("airflow", "apache-airflow"),
    "superset": ("superset", "apache-superset"),
    "metabase": ("metabase", "metabase.com"),
    "nodered": ("node-red", "nodered"),
    "hassio": ("home assistant", "hassio"),
}
DEFAULT_CRED_HINT_SERVICES = {
    "grafana",
    "jenkins",
    "rabbitmq",
    "sonarqube",
    "adminer",
    "phpmyadmin",
    "argocd",
    "portainer",
    "nexus",
    "jfrog",
    "minio",
    "metabase",
}
DEV_ENV_TOKENS = ("dev", "staging", "stage", "test", "qa", "uat", "sandbox", "preview")


def build_service_analysis_results(
    live_records: list[dict[str, Any]],
    open_services: list[dict[str, Any]],
    original_live_hosts: set[str],
    admin_path_limit: int,
    timeout: int,
    limiter: Any,
    deadline_monotonic: float | None = None,
) -> dict[str, list[dict[str, Any]]]:
    records_by_url = {service_url(record): record for record in live_records if service_url(record)}
    http_services = [record for record in live_records if service_url(record)]
    admin_panel_hits = detect_admin_paths(
        http_services,
        admin_path_limit,
        timeout,
        limiter,
        deadline_monotonic=deadline_monotonic,
    )
    return {
        "service_fingerprinting": service_fingerprinting(live_records),
        "default_credential_hints": default_credential_hints(live_records, admin_panel_hits),
        "exposed_service_detection": exposed_service_detection(live_records),
        "tls_ssl_misconfiguration_checks": tls_ssl_misconfiguration_checks(live_records),
        "nonstandard_service_index_detection": nonstandard_service_index_detection(live_records),
        "subdomain_port_mapping": subdomain_port_mapping(live_records),
        "admin_panel_path_detection": admin_panel_hits,
        "http_title_clustering": http_title_clustering(live_records),
        "dev_staging_environment_detection": dev_staging_environment_detection(live_records),
        "port_scan_integration": port_scan_integration(
            open_services, original_live_hosts, records_by_url
        ),
    }


def port_scan_integration(
    open_services: list[dict[str, Any]],
    original_live_hosts: set[str],
    records_by_url: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    findings = []
    for item in open_services:
        url = service_url(item)
        finding = {
            "host": item.get("host", ""),
            "port": item.get("port"),
            "scheme": item.get("scheme", ""),
            "status": "new_http_service"
            if url and url not in original_live_hosts and url in records_by_url
            else "open_service",
            "service_type": item.get("service_type", "tcp"),
        }
        if url:
            finding["url"] = url
        findings.append(finding)
    return findings


def service_fingerprinting(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for record in live_records:
        url = service_url(record)
        if not url:
            continue
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "host": record_host(record),
                "port": record_port(record),
                "http_title": str(record.get("title", "")).strip(),
                "server_header": str((record.get("headers") or {}).get("server", "")),
                "banner": str(record.get("banner", ""))[:120],
                "technologies": sorted(set(detect_services(record))),
            }
        )
    return findings


def default_credential_hints(
    live_records: list[dict[str, Any]], admin_panel_hits: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    admin_urls = {item.get("url", "") for item in admin_panel_hits}
    findings = []
    for record in live_records:
        url = service_url(record)
        if not url:
            continue
        services = set(detect_services(record))
        title = str(record.get("title", "")).lower()
        if (
            not services.intersection(DEFAULT_CRED_HINT_SERVICES)
            and url not in admin_urls
            and "login" not in title
        ):
            continue
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "services": sorted(services),
                "http_title": str(record.get("title", "")),
                "hint": "Review for factory-default credentials, weak bootstrap accounts, or exposed setup wizards.",
            }
        )
    return findings


def exposed_service_detection(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for record in live_records:
        url = service_url(record)
        if not url:
            continue
        services = sorted(set(detect_services(record)))
        if not services:
            continue
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "services": services,
                "http_title": str(record.get("title", "")),
            }
        )
    return findings


def tls_ssl_misconfiguration_checks(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    now = datetime.now(UTC)
    for record in live_records:
        if str(record.get("scheme", "")).lower() != "https":
            continue
        issues = []
        tls = record.get("tls", {}) or {}
        expires_at = str(tls.get("not_after", "")).strip()
        if expires_at:
            try:
                expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if expiry <= now:
                    issues.append("certificate_expired")
            except (ValueError, OSError) as exc:
                logger.debug(
                    "Failed to parse TLS certificate expiry for %s: %s", record.get("host", ""), exc
                )
        if tls.get("self_signed"):
            issues.append("self_signed_certificate")
        negotiated = str(tls.get("version", "")).upper()
        if negotiated in {"TLSV1", "TLSV1.0", "TLS1.0", "TLSV1.1", "TLS1.1"}:
            issues.append("weak_tls_version")
        if not issues:
            continue
        url = service_url(record)
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "issues": issues,
                "tls_version": tls.get("version", ""),
                "not_after": expires_at,
            }
        )
    return findings


def nonstandard_service_index_detection(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for record in live_records:
        url = service_url(record)
        port = record_port(record)
        body = str(record.get("body_excerpt", "")).lower()
        if not url or port in {80, 443}:
            continue
        if "index of /" in body or "directory listing" in body or "parent directory" in body:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "port": port,
                    "indicator": "nonstandard_port_index",
                }
            )
    return findings


def subdomain_port_mapping(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in live_records:
        host = record_host(record)
        if not host:
            continue
        grouped.setdefault(host, []).append(record)
    results: list[dict[str, Any]] = []
    for host, items in grouped.items():
        services = []
        for item in sorted(
            items, key=lambda row: (int(row.get("port", 0)), str(row.get("scheme", "")))
        ):
            services.append(
                {
                    "port": item.get("port"),
                    "scheme": item.get("scheme", ""),
                    "url": service_url(item),
                    "services": sorted(set(detect_services(item))),
                    "title": str(item.get("title", ""))[:80],
                }
            )
        results.append({"host": host, "service_count": len(services), "services": services[:12]})
    results.sort(key=lambda item: (-len(item.get("services", [])), str(item.get("host", ""))))
    return results


def http_title_clustering(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    clusters: dict[str, dict[str, Any]] = {}
    for record in live_records:
        title = normalize_title(str(record.get("title", "")))
        if not title:
            continue
        entry = clusters.setdefault(title, {"title_cluster": title, "count": 0, "urls": []})
        entry["count"] += 1
        url = service_url(record)
        if url and len(entry["urls"]) < 8:
            entry["urls"].append(url)
    results = list(clusters.values())
    results.sort(key=lambda item: (-item["count"], item["title_cluster"]))
    return results


def dev_staging_environment_detection(live_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for record in live_records:
        host = record_host(record).lower()
        title = str(record.get("title", "")).lower()
        body = str(record.get("body_excerpt", "")).lower()
        matched = [
            token for token in DEV_ENV_TOKENS if token in host or token in title or token in body
        ]
        if not matched:
            continue
        url = service_url(record)
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url) if url else "",
                "endpoint_base_key": endpoint_base_key(url) if url else "",
                "endpoint_type": classify_endpoint(url) if url else "GENERAL",
                "host": host,
                "signals": sorted(set(matched)),
            }
        )
    return findings


def detect_admin_paths(
    http_services: list[dict[str, Any]],
    limit: int,
    timeout: int,
    limiter: Any,
    deadline_monotonic: float | None = None,
) -> list[dict[str, Any]]:
    findings = []
    checked = 0
    for record in http_services:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            break
        base_url = service_url(record)
        if not base_url:
            continue
        if checked >= limit:
            break
        for path in ADMIN_PATHS:
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                break
            if checked >= limit:
                break
            checked += 1
            probe_url = f"{base_url}{path}"
            limiter.wait()
            response = fetch_http_details(probe_url, timeout)
            if "error" in response:
                continue
            title = response.get("title", "")
            body = str(response.get("body_excerpt", "")).lower()
            if (
                response.get("status_code", 0) >= 400
                and "login" not in body
                and "admin" not in body
            ):
                continue
            findings.append(
                {
                    "url": probe_url,
                    "endpoint_key": endpoint_signature(probe_url),
                    "endpoint_base_key": endpoint_base_key(probe_url),
                    "endpoint_type": classify_endpoint(probe_url),
                    "status_code": response.get("status_code"),
                    "path": path,
                    "title": title,
                    "indicators": sorted(
                        set(
                            token
                            for token in ("admin", "dashboard", "manage", "login")
                            if token in path or token in title.lower() or token in body
                        )
                    ),
                }
            )
    return findings


def detect_services(record: dict[str, Any]) -> list[str]:
    combined = " ".join(
        [
            str(record.get("title", "")),
            str(record.get("banner", "")),
            str(record.get("body_excerpt", ""))[:1200],
            " ".join(f"{key}:{value}" for key, value in (record.get("headers") or {}).items()),
        ]
    ).lower()
    return [
        label
        for label, markers in SERVICE_SIGNATURES.items()
        if any(marker in combined for marker in markers)
    ]


def empty_service_results() -> dict[str, list[dict[str, Any]]]:
    return {
        "service_fingerprinting": [],
        "default_credential_hints": [],
        "exposed_service_detection": [],
        "tls_ssl_misconfiguration_checks": [],
        "nonstandard_service_index_detection": [],
        "subdomain_port_mapping": [],
        "admin_panel_path_detection": [],
        "http_title_clustering": [],
        "dev_staging_environment_detection": [],
        "port_scan_integration": [],
    }
