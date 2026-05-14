from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_USER_AGENT = "target-specific-pipeline/2.0"
TOOL_NAMES = [
    "subfinder",
    "assetfinder",
    "amass",
    "httpx",
    "gau",
    "waybackurls",
    "katana",
    "nuclei",
]
DIFF_TARGETS = {
    "subdomains": "subdomains.txt",
    "live_hosts": "live_hosts.txt",
    "parameters": "parameters.txt",
    "priority_endpoints": "priority_endpoints.txt",
}


@dataclass
class Config:
    target_name: str
    output_dir: Path
    http_timeout_seconds: int
    mode: str
    cache: dict[str, Any]
    storage: dict[str, Any]
    tools: dict[str, Any]
    httpx: dict[str, Any]
    gau: dict[str, Any]
    waybackurls: dict[str, Any]
    katana: dict[str, Any]
    nuclei: dict[str, Any]
    scoring: dict[str, Any]
    filters: dict[str, Any]
    screenshots: dict[str, Any]
    analysis: dict[str, Any]
    review: dict[str, Any]
    extensions: dict[str, Any]
    concurrency: dict[str, Any]
    output: dict[str, Any]
    notifications: dict[str, Any]
