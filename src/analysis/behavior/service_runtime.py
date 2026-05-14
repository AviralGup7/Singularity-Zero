"""Service analysis runtime for probing open ports and fetching service metadata.

Provides functions for TCP connection testing, HTTP detail fetching, TLS
metadata extraction, and banner grabbing for service enrichment.
"""

import logging
import re
import socket
import ssl
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import requests

from src.core.models import DEFAULT_USER_AGENT
from src.core.utils.url_validation import is_safe_url
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

HTTP_PORTS = {80, 81, 3000, 5000, 5601, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9443}
HTTPS_PORTS = {443, 8443, 9443, 10443}
DEFAULT_PORT_SCAN_TARGETS = [80, 81, 443, 3000, 5000, 5601, 8000, 8080, 8081, 8443, 8888, 9000]
ADMIN_PATHS = ["/admin", "/dashboard", "/manage", "/console", "/login"]


class RateLimiter:
    def __init__(self, rate_per_second: float) -> None:
        self.rate_per_second = max(rate_per_second, 0.1)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                time.sleep(self._next_allowed - now)
                now = time.monotonic()
            self._next_allowed = now + (1.0 / self.rate_per_second)


def candidate_hosts(
    subdomains: set[str], live_records: list[dict[str, Any]], max_hosts: int
) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for record in live_records:
        host = record_host(record)
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    for subdomain in sorted(subdomains):
        host = subdomain.strip().lower()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts[:max_hosts]


def host_has_port(live_records: list[dict[str, Any]], host: str, port: int) -> bool:
    for record in live_records:
        if record_host(record) != host:
            continue
        port_val = record.get("port")
        inferred = infer_port_from_url(str(record.get("url", "")))
        actual = int(port_val) if port_val is not None else inferred
        if actual == port:
            return True
    return False


def probe_open_services(
    scan_hosts: list[str],
    ports: list[int],
    live_records: list[dict[str, Any]],
    *,
    timeout: int,
    workers: int,
    limiter: RateLimiter,
    deadline_monotonic: float | None = None,
) -> list[dict[str, Any]]:
    jobs = [
        (host, port)
        for host in scan_hosts
        for port in ports
        if not host_has_port(live_records, host, port)
    ]
    open_services: list[dict[str, Any]] = []
    if not jobs:
        return open_services
    max_workers = min(workers, len(jobs))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending: dict[Any, tuple[str, int]] = {}
        job_index = 0

        while job_index < len(jobs) and len(pending) < max_workers:
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                return open_services
            host, port = jobs[job_index]
            future = executor.submit(
                probe_service,
                host,
                port,
                timeout,
                limiter,
                deadline_monotonic,
            )
            pending[future] = (host, port)
            job_index += 1

        while pending:
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                for future in pending:
                    future.cancel()
                break

            done, _ = wait(list(pending), timeout=0.2, return_when=FIRST_COMPLETED)
            if not done:
                continue

            for future in done:
                pending.pop(future, None)
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    open_services.append(result)

                if job_index >= len(jobs):
                    continue
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    continue

                host, port = jobs[job_index]
                next_future = executor.submit(
                    probe_service,
                    host,
                    port,
                    timeout,
                    limiter,
                    deadline_monotonic,
                )
                pending[next_future] = (host, port)
                job_index += 1
    return open_services


def probe_service(
    host: str,
    port: int,
    timeout: int,
    limiter: RateLimiter,
    deadline_monotonic: float | None = None,
) -> dict[str, Any] | None:
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return None
    limiter.wait()
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return None
    if not tcp_connect(host, port, timeout):
        return None
    scheme = "https" if port in HTTPS_PORTS else "http" if port in HTTP_PORTS else ""
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "scheme": scheme,
        "service_type": "http" if scheme else "tcp",
        "source": "lightweight-port-scan",
    }
    if scheme:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return None
        url = normalize_url(f"{scheme}://{host}:{port}")
        details = fetch_http_details(url, timeout)
        if "error" not in details:
            result.update(details)
            result["url"] = url
    else:
        result["banner"] = fetch_banner(host, port, timeout)
    if scheme == "https":
        result["tls"] = fetch_tls_metadata(host, port, timeout)
    return result


def tcp_connect(host: str, port: int, timeout: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def fetch_http_details(url: str, timeout: int) -> dict[str, Any]:
    """Fetch HTTP response details including status, headers, title, and body excerpt.

    Args:
        url: Target URL to fetch.
        timeout: Request timeout in seconds.

    Returns:
        Dict with status_code, headers, title, body_excerpt on success,
        or dict with 'error' key on failure.
    """
    if not is_safe_url(url):
        logger.debug("URL failed safety check: %s", url)
        return {"error": "URL failed safety check"}
    headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "text/html,application/json,*/*"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        raw = resp.content[:12000]
        try:
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = resp.text or ""
        resp_headers = {str(k).lower(): str(v) for k, v in dict(resp.headers).items()}
        return {
            "status_code": getattr(resp, "status_code", None),
            "headers": resp_headers,
            "title": extract_title(body),
            "body_excerpt": body[:4000],
        }
    except Exception as exc:
        logger.debug("HTTP fetch failed for %s: %s", url, exc)
        return {"error": str(exc)}


def fetch_tls_metadata(host: str, port: int, timeout: int) -> dict[str, Any]:
    """Fetch TLS certificate metadata including version, expiry, and self-signed status.

    Args:
        host: Target hostname.
        port: Target port number.
        timeout: Connection timeout in seconds.

    Returns:
        Dict with TLS metadata, or dict with 'error' key on failure.
    """
    metadata: dict[str, Any] = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                metadata["version"] = tls_sock.version() or ""
                if cert:
                    subject = cert.get("subject", ())
                    issuer = cert.get("issuer", ())
                    metadata["self_signed"] = bool(subject and subject == issuer)
                    not_after = cert.get("notAfter")
                    if isinstance(not_after, str):
                        parsed = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=UTC
                        )
                        metadata["not_after"] = parsed.isoformat().replace("+00:00", "Z")
    except Exception as exc:
        logger.debug("TLS metadata fetch failed for %s:%d: %s", host, port, exc)
        metadata["error"] = str(exc)
    return metadata


def fetch_banner(host: str, port: int, timeout: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendall(b"\r\n")
            except Exception:  # noqa: BLE001
                pass
            return sock.recv(256).decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def merge_live_records(
    live_records: list[dict[str, Any]], open_services: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    merged = list(live_records)
    seen = {
        normalize_url(str(record.get("url", ""))) for record in live_records if record.get("url")
    }
    for item in open_services:
        url = normalize_url(str(item.get("url", "")))
        if url and url in seen:
            continue
        if url:
            seen.add(url)
        merged.append(item)
    return merged


def service_url(record: dict[str, Any]) -> str:
    url = normalize_url(str(record.get("url", "")))
    return url if url.startswith(("http://", "https://")) else ""


def record_host(record: dict[str, Any]) -> str:
    host_val = record.get("host")
    if host_val:
        return str(host_val).strip().lower()
    parsed = urlparse(str(record.get("url", "")))
    return parsed.hostname.lower() if parsed.hostname else ""


def record_port(record: dict[str, Any]) -> int:
    port_val = record.get("port")
    if port_val is not None:
        return int(port_val)
    return infer_port_from_url(str(record.get("url", "")))


def infer_port_from_url(url: str) -> int:
    parsed = urlparse(url)
    if parsed.port:
        return int(parsed.port)
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return 0


def extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""


def normalize_title(title: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", title.lower())).strip()
