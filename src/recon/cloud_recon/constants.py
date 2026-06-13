from __future__ import annotations

from typing import Any

DEFAULT_S3_WEBSITE_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-west-2",
    "eu-west-1",
)

_S3_COMMON_OBJECT_PATHS: tuple[str, ...] = (
    "index.html",
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "readme.md",
    "README",
    "static/index.html",
)

_GCP_CLOUD_RUN_REGION_TEMPLATES: tuple[str, ...] = (
    "-uc.a.run.app",
    "-us-central1.a.run.app",
    "-us-east1.a.run.app",
    "-europe-west1.a.run.app",
    "-asia-east1.a.run.app",
)

_GCP_CLOUD_RUN_SERVICE_HINTS: tuple[str, ...] = (
    "api",
    "app",
    "web",
    "service",
    "backend",
    "frontend",
    "auth",
    "proxy",
    "gateway",
    "cdn",
    "webhook",
    "worker",
)

_DEFAULT_AWS_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "sa-east-1",
)

_DEFAULT_GCP_REGIONS: tuple[str, ...] = (
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "southamerica-east1",
)

_AZURE_FUNCTIONS_REGIONS: tuple[str, ...] = (
    "us",
    "us2",
    "us3",
    "europe",
    "asia",
    "australia",
    "india",
    "canada",
    "uk",
    "germany",
    "japan",
    "korea",
    "brazil",
    "southafrica",
    "uae",
)

_OCI_REGIONS: tuple[str, ...] = (
    "us-ashburn-1",
    "us-luke-1",
    "us-gov-phx-1",
    "ca-toronto-1",
    "sa-saopaulo-1",
    "eu-amsterdam-1",
    "eu-frankfurt-1",
    "uk-london-1",
    "ap-mumbai-1",
    "ap-osaka-1",
    "ap-seoul-1",
    "ap-sydney-1",
    "ap-tokyo-1",
)

_WASABI_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-central-1",
    "eu-west-1",
    "ap-northeast-1",
    "ap-southeast-1",
)

_DO_REGIONS: tuple[str, ...] = (
    "nyc3",
    "sfo2",
    "nyc1",
    "ams3",
    "sgp1",
    "lon1",
    "fra1",
    "tor1",
    "sfo3",
    "blr1",
    "syd1",
)

_BACKBLAZE_REGIONS: tuple[str, ...] = (
    "us-west-002",
    "us-west-001",
    "us-east-005",
    "eu-central-001",
    "apac-001",
)
