"""Cloud Metadata & Infrastructure Exposure Check.

Analyzes responses and URLs for cloud metadata endpoint exposure,
cloud storage misconfigurations, and exposed infrastructure services.
Produces findings with category "cloud_metadata_exposure".
"""

import re
from typing import Any

from src.analysis.active.cloud_metadata import (
    CLOUD_METADATA_ENDPOINTS,
    CLOUD_STORAGE_PATHS,
    INFRASTRUCTURE_SERVICE_PATHS,
)
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers.scoring import severity_score
from src.analysis.plugins import AnalysisPluginSpec

CLOUD_METADATA_CHECK_SPEC = AnalysisPluginSpec(
    key="cloud_metadata_exposure_checker",
    label="Cloud Metadata Exposure",
    description="Detect cloud provider metadata endpoints (AWS IMDS, GCP, Azure), cloud storage bucket exposure, and exposed infrastructure services (Docker, Kubernetes, Redis, etc.) in URLs and response bodies.",
    group="exposure",
    slug="cloud_metadata_exposure",
    enabled_by_default=True,
)

_METADATA_URL_RE = re.compile(
    r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
    re.IGNORECASE,
)

_METADATA_BODY_TOKENS = (
    "ami-id",
    "instance-id",
    "instance-type",
    "local-ipv4",
    "public-ipv4",
    "iam/security-credentials",
    "hostname",
    "placement/availability-zone",
    "computeMetadata",
    "metadata/instance",
    "metadata/v1",
    "latest/meta-data",
    "latest/user-data",
)

_STORAGE_BODY_TOKENS = (
    "<ListBucketResult",
    "<Contents>",
    "NoSuchBucket",
    "AccessDenied",
    "AnonymousUser",
    "x-amz-request-id",
    "x-amz-id-2",
    "PublicAccess",
    "BlobNotFound",
    "ContainerNotFound",
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "digitaloceanspaces.com",
    "r2.cloudflarestorage.com",
    "minio",
)

_INFRA_BODY_TOKENS = (
    '"ApiVersion"',
    '"KernelVersion"',
    '"DockerRootDir"',
    '"kind": "PodList"',
    '"kind": "NamespaceList"',
    '"apiVersion": "v1"',
    "redis_version",
    "redis_build_id",
    '"etcdserver"',
    '"etcdcluster"',
    '"cluster_name"',
    '"number_of_nodes"',
    "promhttp_metric_handler_requests",
    "go_goroutines",
    '"isGrafanaAdmin"',
    '"management_version"',
)

_CLOUD_PATH_TOKENS = tuple(
    list(CLOUD_STORAGE_PATHS)
    + [p for paths in INFRASTRUCTURE_SERVICE_PATHS.values() for p in paths]
    + [ep for endpoints in CLOUD_METADATA_ENDPOINTS.values() for ep in endpoints]
)


def _build_finding(
    url: str,
    severity: str,
    title: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": "cloud_metadata_exposure",
        "title": title,
        "severity": severity,
        "confidence": 0.85
        if severity in ("critical", "high")
        else 0.7
        if severity == "medium"
        else 0.5,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }


def cloud_metadata_exposure_checker(
    urls: set[str],
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Check for cloud metadata, storage, and infrastructure exposure signals.

    Scans URLs for references to cloud metadata endpoints and probes
    common infrastructure paths. Scans response bodies for metadata
    content patterns, storage bucket indicators, and infrastructure
    service fingerprints.

    Args:
        urls: Set of URLs discovered during reconnaissance.
        responses: List of HTTP response dicts with url, body_text, headers, etc.

    Returns:
        List of finding dicts with cloud metadata exposure signals.
    """
    findings: list[dict[str, Any]] = []
    seen_metadata: set[str] = set()
    seen_storage: set[str] = set()
    seen_infra: set[str] = set()
    seen_path: set[str] = set()

    for url in sorted(urls):
        url_lower = url.lower()

        if _METADATA_URL_RE.search(url):
            dedupe_key = f"metadata_url:{url}"
            if dedupe_key not in seen_metadata:
                seen_metadata.add(dedupe_key)
                findings.append(
                    _build_finding(
                        url=url,
                        severity="high",
                        title=f"Cloud metadata endpoint reference in URL: {url}",
                        signals=["cloud_metadata_url_reference"],
                        evidence={"url": url, "source": "url_scan"},
                        explanation=(
                            f"URL '{url}' contains a reference to a known cloud provider "
                            f"metadata endpoint. This may indicate SSRF-style access "
                            f"to internal metadata services."
                        ),
                    )
                )

        for path_token in _CLOUD_PATH_TOKENS:
            if path_token.lower() in url_lower:
                dedupe_key = f"path:{path_token}:{url}"
                if dedupe_key not in seen_path:
                    seen_path.add(dedupe_key)
                    findings.append(
                        _build_finding(
                            url=url,
                            severity="low",
                            title=f"Cloud/infrastructure path hint in URL: {path_token}",
                            signals=[f"cloud_path_hint:{path_token}"],
                            evidence={"url": url, "path_token": path_token},
                            explanation=(
                                f"URL '{url}' contains path '{path_token}' which matches "
                                f"a known cloud metadata, storage, or infrastructure service path."
                            ),
                        )
                    )
                break

    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if not resp_url:
            continue
        body = str(resp.get("body_text") or "")[:12000]
        body_lower = body.lower()
        status_code = resp.get("status_code")
        headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}

        if _METADATA_URL_RE.search(body):
            dedupe_key = f"metadata_body:{resp_url}"
            if dedupe_key not in seen_metadata:
                seen_metadata.add(dedupe_key)
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="high",
                        title="Cloud metadata endpoint reference in response body",
                        signals=["cloud_metadata_body_reference"],
                        evidence={
                            "url": resp_url,
                            "source": "response_body",
                            "status_code": status_code,
                        },
                        explanation=(
                            f"Response from '{resp_url}' contains references to cloud "
                            f"provider metadata endpoints. This may indicate the application "
                            f"proxies or forwards requests to internal metadata services."
                        ),
                        status_code=status_code,
                    )
                )

        metadata_hits = [t for t in _METADATA_BODY_TOKENS if t.lower() in body_lower]
        if metadata_hits:
            dedupe_key = f"metadata_tokens:{resp_url}"
            if dedupe_key not in seen_metadata:
                seen_metadata.add(dedupe_key)
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="high",
                        title="Cloud metadata content detected in response",
                        signals=[f"metadata_token:{t}" for t in metadata_hits[:5]],
                        evidence={
                            "url": resp_url,
                            "matched_tokens": metadata_hits[:5],
                            "source": "response_body",
                            "status_code": status_code,
                        },
                        explanation=(
                            f"Response from '{resp_url}' contains cloud metadata content "
                            f"patterns: {', '.join(metadata_hits[:5])}. This suggests "
                            f"exposure of instance metadata or configuration data."
                        ),
                        status_code=status_code,
                    )
                )

        storage_hits = [t for t in _STORAGE_BODY_TOKENS if t.lower() in body_lower]
        if storage_hits:
            dedupe_key = f"storage_tokens:{resp_url}"
            if dedupe_key not in seen_storage:
                seen_storage.add(dedupe_key)
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="medium",
                        title="Cloud storage indicator detected in response",
                        signals=[f"storage_indicator:{t}" for t in storage_hits[:5]],
                        evidence={
                            "url": resp_url,
                            "matched_tokens": storage_hits[:5],
                            "source": "response_body",
                            "status_code": status_code,
                        },
                        explanation=(
                            f"Response from '{resp_url}' contains cloud storage "
                            f"indicators: {', '.join(storage_hits[:5])}. This may "
                            f"indicate exposed bucket listings or storage API responses."
                        ),
                        status_code=status_code,
                    )
                )

        infra_hits = [t for t in _INFRA_BODY_TOKENS if t.lower() in body_lower]
        if infra_hits:
            dedupe_key = f"infra_tokens:{resp_url}"
            if dedupe_key not in seen_infra:
                seen_infra.add(dedupe_key)
                service_hint = _classify_infra_service(infra_hits)
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="high",
                        title=f"Infrastructure service fingerprint detected: {service_hint}",
                        signals=[f"infra_fingerprint:{t}" for t in infra_hits[:5]],
                        evidence={
                            "url": resp_url,
                            "service_hint": service_hint,
                            "matched_tokens": infra_hits[:5],
                            "source": "response_body",
                            "status_code": status_code,
                        },
                        explanation=(
                            f"Response from '{resp_url}' contains infrastructure service "
                            f"fingerprint for '{service_hint}': {', '.join(infra_hits[:5])}. "
                            f"This suggests exposure of internal management interfaces."
                        ),
                        status_code=status_code,
                    )
                )

        cloud_headers = _check_cloud_headers(headers)
        if cloud_headers:
            dedupe_key = f"cloud_headers:{resp_url}"
            if dedupe_key not in seen_infra:
                seen_infra.add(dedupe_key)
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="low",
                        title="Cloud provider headers detected in response",
                        signals=[f"cloud_header:{h}" for h in cloud_headers[:5]],
                        evidence={
                            "url": resp_url,
                            "cloud_headers": cloud_headers,
                            "source": "response_headers",
                            "status_code": status_code,
                        },
                        explanation=(
                            f"Response from '{resp_url}' includes cloud provider-specific "
                            f"headers: {', '.join(cloud_headers[:5])}. This indicates the "
                            f"application runs on or proxies through cloud infrastructure."
                        ),
                        status_code=status_code,
                    )
                )

    return findings[:200]


def _classify_infra_service(hits: list[str]) -> str:
    docker_tokens = ('"ApiVersion"', '"KernelVersion"', '"DockerRootDir"')
    k8s_tokens = ('"kind": "PodList"', '"kind": "NamespaceList"', '"apiVersion": "v1"')
    redis_tokens = ("redis_version", "redis_build_id")
    etcd_tokens = ('"etcdserver"', '"etcdcluster"')
    elastic_tokens = ('"cluster_name"', '"number_of_nodes"')
    prometheus_tokens = ("promhttp_metric_handler_requests", "go_goroutines")
    grafana_tokens = ('"isGrafanaAdmin"', '"dashboards"')
    rabbitmq_tokens = ('"management_version"', '"queue_totals"')

    for token in hits:
        if token in docker_tokens:
            return "docker_api"
        if token in k8s_tokens:
            return "kubernetes_api"
        if token in redis_tokens:
            return "redis"
        if token in etcd_tokens:
            return "etcd"
        if token in elastic_tokens:
            return "elasticsearch"
        if token in prometheus_tokens:
            return "prometheus"
        if token in grafana_tokens:
            return "grafana"
        if token in rabbitmq_tokens:
            return "rabbitmq"
    return "unknown_infrastructure"


def _check_cloud_headers(headers: dict[str, str]) -> list[str]:
    cloud_header_map = {
        "x-amz-request-id": "aws_s3",
        "x-amz-id-2": "aws_s3",
        "x-amz-cf-id": "aws_cloudfront",
        "x-goog-request-id": "gcs",
        "x-ms-request-id": "azure_blob",
        "x-ms-version": "azure_blob",
        "x-r2-request-id": "cloudflare_r2",
        "x-do-request-id": "digitalocean_spaces",
    }
    return [service for header, service in cloud_header_map.items() if header in headers]
