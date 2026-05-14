"""Cloud metadata and infrastructure exposure probes.

Tests for cloud provider metadata endpoints (AWS IMDSv1/v2, GCP metadata,
Azure IMDS, DigitalOcean, Alibaba), cloud storage bucket misconfigurations,
and exposed infrastructure services (Docker API, Kubernetes API, Redis, etc.).

These probes are designed to detect whether the TARGET application exposes
these endpoints (e.g. via SSRF or misconfigured reverse proxies), NOT to
scan the local machine.
"""

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)
from .cloud_constants import (
    AZURE_METADATA_HEADER,
    CLOUD_METADATA_ENDPOINTS,
    CLOUD_STORAGE_PATHS,
    GCP_METADATA_HEADER,
    IMDSV2_TOKEN_HEADER,
    INFRASTRUCTURE_SERVICE_PATHS,
)


def probe_cloud_metadata(url: str, session) -> dict[str, Any]:
    """Test if cloud metadata endpoints are accessible through the target.

    Attempts to reach known cloud provider metadata endpoints by appending
    them to the target's base URL. This detects SSRF-style exposure where
    the target application proxies or forwards requests to internal metadata
    services.

    Args:
        url: Base URL of the target application.
        session: HTTP session for making requests.

    Returns:
        Dict with findings about accessible metadata endpoints.
    """
    findings: list[dict[str, Any]] = []
    base_url = _get_base_url(url)

    for provider, endpoints in CLOUD_METADATA_ENDPOINTS.items():
        for endpoint in endpoints:
            probe_url = urljoin(base_url, endpoint)
            try:
                headers = {
                    AZURE_METADATA_HEADER: "true",
                    GCP_METADATA_HEADER: "Google",
                }
                resp = session.get(probe_url, headers=headers, timeout=8, allow_redirects=False)
                status = resp.status_code if resp is not None else 0
                body = (resp.text if resp is not None else "")[:4000]

                if status == 200 and len(body) > 10:
                    severity = (
                        "critical"
                        if provider in ("aws_imds", "gcp_metadata", "azure_imds")
                        else "high"
                    )
                    findings.append(
                        {
                            "provider": provider,
                            "endpoint": endpoint,
                            "probe_url": probe_url,
                            "status_code": status,
                            "severity": severity,
                            "indicator": f"{provider}_accessible",
                            "evidence_preview": body[:500],
                        }
                    )
                    logger.warning(
                        "Cloud metadata endpoint accessible: %s -> %s (status %s)",
                        provider,
                        probe_url,
                        status,
                    )
                elif status in (401, 403):
                    findings.append(
                        {
                            "provider": provider,
                            "endpoint": endpoint,
                            "probe_url": probe_url,
                            "status_code": status,
                            "severity": "medium",
                            "indicator": f"{provider}_requires_auth",
                        }
                    )
            except Exception as exc:
                logger.debug("Probe failed for %s: %s", probe_url, exc)

    try:
        for endpoint in CLOUD_METADATA_ENDPOINTS.get("aws_imds", []):
            probe_url = urljoin(base_url, endpoint)
            headers = {IMDSV2_TOKEN_HEADER: "session-token-test"}
            resp = session.get(probe_url, headers=headers, timeout=8, allow_redirects=False)
            status = resp.status_code if resp is not None else 0
            if status == 200:
                body = (resp.text if resp is not None else "")[:4000]
                if len(body) > 10:
                    findings.append(
                        {
                            "provider": "aws_imds_v2_bypass",
                            "endpoint": endpoint,
                            "probe_url": probe_url,
                            "status_code": status,
                            "severity": "critical",
                            "indicator": "aws_imds_v2_token_bypass",
                            "evidence_preview": body[:500],
                        }
                    )
                    logger.warning(
                        "AWS IMDSv2 token bypass detected: %s",
                        probe_url,
                    )
    except Exception as exc:
        logger.debug("IMDSv2 token bypass probe failed: %s", exc)

    return {
        "probe": "cloud_metadata",
        "target": base_url,
        "findings": findings,
        "accessible_count": len([f for f in findings if f.get("status_code") == 200]),
    }


def probe_cloud_storage_exposure(url: str, session) -> dict[str, Any]:
    """Test for cloud storage bucket misconfigurations through the target.

    Probes common storage-related paths on the target to detect exposed
    S3-compatible APIs, GCS proxies, Azure Blob endpoints, or internal
    storage management interfaces.

    Args:
        url: Base URL of the target application.
        session: HTTP session for making requests.

    Returns:
        Dict with findings about exposed cloud storage interfaces.
    """
    findings: list[dict[str, Any]] = []
    base_url = _get_base_url(url)

    storage_indicators = (
        "<ListBucketResult",
        "<IsTruncated>",
        "<Contents>",
        "<Key>",
        "<Name>",
        "NoSuchBucket",
        "AccessDenied",
        "AnonymousUser",
        "x-amz-request-id",
        "x-amz-id-2",
        "ListBucketResult",
        "PublicAccess",
        "BlobNotFound",
        "ContainerNotFound",
        "storage.googleapis.com",
        "s3.amazonaws.com",
        "blob.core.windows.net",
        "digitaloceanspaces.com",
        "r2.cloudflarestorage.com",
        "minio",
        "minioadmin",
    )

    for path in CLOUD_STORAGE_PATHS:
        probe_url = urljoin(base_url, path)
        try:
            resp = session.get(probe_url, timeout=8, allow_redirects=False)
            status = resp.status_code if resp is not None else 0
            body = (resp.text if resp is not None else "")[:4000].lower()

            if status == 200 and len(body) > 20:
                matched_indicators = [ind for ind in storage_indicators if ind.lower() in body]
                if matched_indicators:
                    findings.append(
                        {
                            "path": path,
                            "probe_url": probe_url,
                            "status_code": status,
                            "severity": "high",
                            "indicator": "cloud_storage_accessible",
                            "matched_indicators": matched_indicators[:5],
                            "evidence_preview": (resp.text if resp is not None else "")[:500],
                        }
                    )
                    logger.warning(
                        "Cloud storage path accessible: %s (status %s)",
                        probe_url,
                        status,
                    )
                else:
                    findings.append(
                        {
                            "path": path,
                            "probe_url": probe_url,
                            "status_code": status,
                            "severity": "low",
                            "indicator": "storage_path_responds",
                        }
                    )
            elif status in (401, 403):
                findings.append(
                    {
                        "path": path,
                        "probe_url": probe_url,
                        "status_code": status,
                        "severity": "info",
                        "indicator": "storage_path_requires_auth",
                    }
                )
        except Exception as exc:
            logger.debug("Storage probe failed for %s: %s", probe_url, exc)

    return {
        "probe": "cloud_storage_exposure",
        "target": base_url,
        "findings": findings,
        "accessible_count": len([f for f in findings if f.get("status_code") == 200]),
    }


def probe_infrastructure_services(url: str, session) -> dict[str, Any]:
    """Test for exposed infrastructure management services.

    Probes for Docker API, Kubernetes API, Redis, Elasticsearch,
    Prometheus, Grafana, and other infrastructure services that may
    be exposed through the target application.

    Args:
        url: Base URL of the target application.
        session: HTTP session for making requests.

    Returns:
        Dict with findings about exposed infrastructure services.
    """
    findings: list[dict[str, Any]] = []
    base_url = _get_base_url(url)

    service_indicators: dict[str, tuple[str, ...]] = {
        "docker_api": (
            '"ApiVersion"',
            '"Arch"',
            '"Os"',
            '"KernelVersion"',
            '"ContainersRunning"',
            '"Images"',
            '"DockerRootDir"',
        ),
        "kubernetes_api": (
            '"kind": "PodList"',
            '"kind": "NamespaceList"',
            '"kind": "ServiceList"',
            '"kind": "NodeList"',
            '"apiVersion": "v1"',
            '"resourceVersion"',
        ),
        "redis_info": (
            "redis_version",
            "redis_build_id",
            "redis_mode",
            "used_memory:",
            "used_memory_peak:",
        ),
        "etcd": (
            '"etcdserver"',
            '"etcdcluster"',
            '"members"',
        ),
        "consul": (
            '"Config"',
            '"Member"',
            '"Datacenter"',
            '"SerfLan"',
        ),
        "elasticsearch": (
            '"cluster_name"',
            '"status":',
            '"number_of_nodes"',
            '"active_shards"',
            '"version":',
        ),
        "prometheus": (
            "promhttp_metric_handler_requests",
            "go_goroutines",
            "process_cpu_seconds_total",
            "# HELP",
        ),
        "grafana": (
            '"login":',
            '"isGrafanaAdmin"',
            '"theme":',
            '"dashboards"',
            '"orgId"',
        ),
        "rabbitmq": (
            '"cluster_name"',
            '"management_version"',
            '"queue_totals"',
        ),
    }

    for service_name, paths in INFRASTRUCTURE_SERVICE_PATHS.items():
        for path in paths:
            probe_url = urljoin(base_url, path)
            try:
                resp = session.get(probe_url, timeout=8, allow_redirects=False)
                status = resp.status_code if resp is not None else 0
                body = (resp.text if resp is not None else "")[:4000]
                body_lower = body.lower()

                if status == 200 and len(body) > 20:
                    indicators = service_indicators.get(service_name, ())
                    matched = [ind for ind in indicators if ind.lower() in body_lower]

                    if matched:
                        severity = (
                            "critical"
                            if service_name
                            in ("docker_api", "kubernetes_api", "redis_info", "etcd")
                            else "high"
                        )
                        findings.append(
                            {
                                "service": service_name,
                                "path": path,
                                "probe_url": probe_url,
                                "status_code": status,
                                "severity": severity,
                                "indicator": f"{service_name}_exposed",
                                "matched_indicators": matched[:5],
                                "evidence_preview": body[:500],
                            }
                        )
                        logger.warning(
                            "Infrastructure service exposed: %s at %s (status %s)",
                            service_name,
                            probe_url,
                            status,
                        )
                    else:
                        findings.append(
                            {
                                "service": service_name,
                                "path": path,
                                "probe_url": probe_url,
                                "status_code": status,
                                "severity": "low",
                                "indicator": f"{service_name}_path_responds",
                            }
                        )
                elif status in (401, 403):
                    findings.append(
                        {
                            "service": service_name,
                            "path": path,
                            "probe_url": probe_url,
                            "status_code": status,
                            "severity": "info",
                            "indicator": f"{service_name}_requires_auth",
                        }
                    )
            except Exception as exc:
                logger.debug("Infrastructure probe failed for %s: %s", probe_url, exc)

    return {
        "probe": "infrastructure_services",
        "target": base_url,
        "findings": findings,
        "accessible_count": len([f for f in findings if f.get("status_code") == 200]),
    }


def run_cloud_metadata_probes(
    urls: list[str], session, config: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Main entry point for cloud metadata and infrastructure exposure testing.

    Runs all three probe categories (metadata, storage, infrastructure)
    against each target URL and aggregates findings.

    Args:
        urls: List of target URLs to probe.
        session: HTTP session for making requests.
        config: Optional configuration dict with probe settings.

    Returns:
        Aggregated results dict with all findings grouped by probe type.
    """
    config = config or {}
    all_results: dict[str, Any] = {
        "metadata_probes": [],
        "storage_probes": [],
        "infrastructure_probes": [],
        "total_findings": 0,
        "critical_findings": 0,
        "high_findings": 0,
    }

    for target_url in urls:
        try:
            metadata_result = probe_cloud_metadata(target_url, session)
            all_results["metadata_probes"].append(metadata_result)

            storage_result = probe_cloud_storage_exposure(target_url, session)
            all_results["storage_probes"].append(storage_result)

            infra_result = probe_infrastructure_services(target_url, session)
            all_results["infrastructure_probes"].append(infra_result)

            for result in (metadata_result, storage_result, infra_result):
                findings = result.get("findings", [])
                all_results["total_findings"] += len(findings)
                for finding in findings:
                    sev = finding.get("severity", "").lower()
                    if sev == "critical":
                        all_results["critical_findings"] += 1
                    elif sev == "high":
                        all_results["high_findings"] += 1

        except Exception as exc:
            logger.error("Cloud metadata probe failed for %s: %s", target_url, exc)
            all_results["metadata_probes"].append(
                {
                    "probe": "cloud_metadata",
                    "target": target_url,
                    "error": str(exc),
                    "findings": [],
                }
            )

    return all_results


def cloud_metadata_active_probe(targets: list[str], limit: int = 25) -> list[dict[str, Any]]:
    """Run cloud metadata and infrastructure probes for active scan targets."""
    if not targets:
        return []

    try:
        from requests import Session
    except Exception as exc:  # pragma: no cover - environment-specific
        logger.warning("Cloud metadata probe disabled: requests not available: %s", exc)
        return []

    from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

    normalized_targets: list[str] = []
    for item in targets:
        value = str(item or "").strip()
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            normalized_targets.append(value)
        else:
            normalized_targets.append(f"https://{value}")
            normalized_targets.append(f"http://{value}")

    findings: list[dict[str, Any]] = []
    with Session() as session:
        probe_results = run_cloud_metadata_probes(normalized_targets, session)

    for bucket_key in ("metadata_probes", "storage_probes", "infrastructure_probes"):
        bucket = probe_results.get(bucket_key, [])
        if not isinstance(bucket, list):
            continue
        for probe_entry in bucket:
            if not isinstance(probe_entry, dict):
                continue
            target = str(probe_entry.get("target", "")).strip()
            raw_findings = probe_entry.get("findings", [])
            if not isinstance(raw_findings, list):
                continue
            for raw_finding in raw_findings:
                if len(findings) >= limit:
                    return findings
                if not isinstance(raw_finding, dict):
                    continue
                url = str(raw_finding.get("probe_url", "")).strip() or target
                if not url:
                    continue
                severity = str(raw_finding.get("severity", "medium") or "medium").lower()
                confidence = (
                    0.9
                    if severity in {"critical", "high"}
                    else 0.72
                    if severity == "medium"
                    else 0.55
                )
                indicator = str(
                    raw_finding.get("indicator", "cloud_metadata_signal") or "cloud_metadata_signal"
                )
                try:
                    endpoint_key = endpoint_signature(url)
                    endpoint_base = endpoint_base_key(url)
                    endpoint_type = classify_endpoint(url)
                except Exception:
                    endpoint_key = url
                    endpoint_base = url
                    endpoint_type = "GENERAL"
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base,
                        "endpoint_type": endpoint_type,
                        "issues": [indicator],
                        "severity": severity,
                        "confidence": confidence,
                        "metadata": raw_finding,
                    }
                )
    return findings


def _get_base_url(url: str) -> str:
    """Extract the base URL (scheme + host) from a full URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
