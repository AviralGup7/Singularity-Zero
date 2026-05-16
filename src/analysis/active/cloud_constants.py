"""Shared constants for cloud metadata and infrastructure probes.

Extracted from cloud_metadata.py to make the probe logic smaller
and more focused.
"""

CLOUD_METADATA_ENDPOINTS: dict[str, list[str]] = {
    "aws_imds": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
    ],
    "gcp_metadata": [
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "azure_imds": [
        "http://169.254.169.254/metadata/instance",
    ],
    "digitalocean_metadata": [
        "http://169.254.169.254/metadata/v1/",
    ],
    "alibaba_metadata": [
        "http://100.100.100.200/latest/meta-data/",
    ],
}

CLOUD_STORAGE_PATHS: list[str] = [
    "/.well-known/aws/metadata",
    "/s3",
    "/bucket",
    "/storage",
    "/cloud-storage",
    "/gcs",
    "/azure-blob",
    "/blob",
    "/minio",
    "/nfs",
    "/mnt",
    "/backup",
    "/data-dump",
    "/export",
    "/dump",
]

INFRASTRUCTURE_SERVICE_PATHS: dict[str, list[str]] = {
    "docker_api": [
        "/version",
        "/info",
        "/containers/json",
        "/images/json",
        "/v1.24/containers/json",
        "/v1.24/info",
    ],
    "kubernetes_api": [
        "/api",
        "/api/v1",
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/services",
        "/api/v1/nodes",
        "/healthz",
        "/readyz",
        "/version",
    ],
    "redis_info": [
        "/redis/info",
        "/redis/stats",
        "/redis",
    ],
    "etcd": [
        "/v2/keys",
        "/v3/kv/put",
        "/version",
    ],
    "consul": [
        "/v1/agent/self",
        "/v1/catalog/services",
        "/v1/status/leader",
    ],
    "jenkins": [
        "/jenkins/script",
        "/jenkins/manage",
        "/script",
    ],
    "elasticsearch": [
        "/_cat/indices",
        "/_cluster/health",
        "/_nodes",
        "/_cluster/state",
    ],
    "prometheus": [
        "/api/v1/query",
        "/metrics",
        "/-/ready",
        "/-/healthy",
    ],
    "grafana": [
        "/api/org",
        "/api/users",
        "/api/dashboards",
    ],
    "mongodb_express": [
        "/db/",
        "/server-status",
    ],
    "rabbitmq": [
        "/api/overview",
        "/api/queues",
        "/api/exchanges",
    ],
}

IMDSV2_TOKEN_HEADER = "X-aws-ec2-metadata-token"  # nosec: S105
GCP_METADATA_HEADER = "Metadata-Flavor"
AZURE_METADATA_HEADER = "Metadata"

__all__ = [
    "CLOUD_METADATA_ENDPOINTS",
    "CLOUD_STORAGE_PATHS",
    "INFRASTRUCTURE_SERVICE_PATHS",
    "IMDSV2_TOKEN_HEADER",
    "GCP_METADATA_HEADER",
    "AZURE_METADATA_HEADER",
]
