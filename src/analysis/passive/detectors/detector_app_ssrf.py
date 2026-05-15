"""Application-specific SSRF vector detection (passive).

Scans response bodies for fingerprints of applications known to have
SSRF-prone features. When detected, flags known exploitable endpoints
for active testing.

Each fingerprint maps to a set of SSRF-vulnerable paths documented
in security advisories, bug bounty write-ups, and CVE databases.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

APP_SIGNATURES: dict[str, dict[str, Any]] = {
    "grafana": {
        "patterns": [
            re.compile(r"grafana", re.IGNORECASE),
            re.compile(r"/public/build/", re.IGNORECASE),
            re.compile(r"/api/datasources", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r'"version"\s*:\s*"([^"]+)"'),
        ],
        "ssrf_endpoints": [
            {
                "path": "/api/datasources",
                "method": "POST",
                "vector": "Create datasource with access=proxy, then use /api/datasources/proxy/{id}/",
            },
            {
                "path": "/api/alert-notifications",
                "method": "POST",
                "vector": "Create webhook notification with attacker-controlled URL",
            },
            {
                "path": "/api/datasources/proxy/{id}/",
                "method": "GET",
                "vector": "Proxy endpoint forwards arbitrary server-side requests",
            },
        ],
    },
    "kibana": {
        "patterns": [
            re.compile(r"kibana", re.IGNORECASE),
            re.compile(r"kbn-name", re.IGNORECASE),
            re.compile(r"/api/status", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r'"number"\s*:\s*"([^"]+)"'),
        ],
        "ssrf_endpoints": [
            {
                "path": "/api/console/proxy",
                "method": "POST",
                "vector": "Console proxy can forward requests to internal Elasticsearch or other services",
            },
            {
                "path": "/api/saved_objects/_import",
                "method": "POST",
                "vector": "Import endpoint can resolve remote URLs during data restoration",
            },
        ],
    },
    "jenkins": {
        "patterns": [
            re.compile(r"jenkins", re.IGNORECASE),
            re.compile(r"/login\?from=", re.IGNORECASE),
            re.compile(r"X-Jenkins", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r"X-Jenkins:\s*(\S+)", re.IGNORECASE),
        ],
        "ssrf_endpoints": [
            {
                "path": "/computer/(master)/log",
                "method": "GET",
                "vector": "Jenkins agent logs fetched from remote agents can be manipulated",
            },
            {
                "path": "/descriptorByName/hudson.plugins.git.GitSCM/fillCredentialsIdItems",
                "method": "POST",
                "vector": "Git SCM credential resolver can trigger server-side DNS resolution",
            },
            {
                "path": "/plugin/credentials",
                "method": "POST",
                "vector": "Credential store lookups can trigger SSRF via URL resolution",
            },
        ],
    },
    "gitlab": {
        "patterns": [
            re.compile(r"gitlab", re.IGNORECASE),
            re.compile(r"gitlab-rails", re.IGNORECASE),
            re.compile(r"/users/sign_in", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r'"version"\s*:\s*"([^"]+)"'),
        ],
        "ssrf_endpoints": [
            {
                "path": "/api/v4/projects",
                "method": "POST",
                "vector": "Import from URL endpoint (import/gitlab_project) resolves external URLs",
            },
            {
                "path": "/api/v4/projects/:id/services",
                "method": "PUT",
                "vector": "Webhook services (Slack, Jira, etc.) can be pointed to internal URLs",
            },
            {
                "path": "/api/v4/import/github",
                "method": "POST",
                "vector": "GitHub import endpoint fetches data from user-supplied URLs",
            },
        ],
    },
    "jira": {
        "patterns": [
            re.compile(r"jira", re.IGNORECASE),
            re.compile(r"atlassian", re.IGNORECASE),
            re.compile(r"/jira/secure/Dashboard\.jspa", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r"'version'\s*:\s*'([^']+)'"),
        ],
        "ssrf_endpoints": [
            {
                "path": "/plugins/servlet/oauth/users/icon-uri",
                "method": "GET",
                "vector": "OAuth icon URL is fetched server-side (CVE-2019-8451)",
            },
            {
                "path": "/rest/api/2/user/picker",
                "method": "GET",
                "vector": "User picker can resolve external resources",
            },
            {
                "path": "/secure/ContactAdministrators!default.jspa",
                "method": "POST",
                "vector": "Contact form can redirect to attacker-controlled URLs",
            },
        ],
    },
    "confluence": {
        "patterns": [
            re.compile(r"confluence", re.IGNORECASE),
            re.compile(r"atlassian-confluence", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r"'version'\s*:\s*'([^']+)'"),
        ],
        "ssrf_endpoints": [
            {
                "path": "/plugins/servlet/gadgets/makeRequest",
                "method": "GET",
                "vector": "Gadgets makeRequest fetches arbitrary URLs server-side (CVE-2019-3396)",
            },
            {
                "path": "/plugins/servlet/oauth/users/icon-uri",
                "method": "GET",
                "vector": "OAuth icon URL fetched server-side (CVE-2019-3395)",
            },
        ],
    },
    "nexus": {
        "patterns": [
            re.compile(r"nexus", re.IGNORECASE),
            re.compile(r"/service/rest/", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r"X-Request-Id:", re.IGNORECASE),
        ],
        "ssrf_endpoints": [
            {
                "path": "/service/rest/beta/repositories/go/group",
                "method": "POST",
                "vector": "Go group repository proxy resolution can fetch from attacker URLs",
            },
            {
                "path": "/service/rest/beta/security/ldap",
                "method": "POST",
                "vector": "LDAP configuration can point to internal services",
            },
        ],
    },
    "artifactory": {
        "patterns": [
            re.compile(r"artifactory", re.IGNORECASE),
            re.compile(r"/artifactory/api/", re.IGNORECASE),
        ],
        "version_patterns": [
            re.compile(r'"version"\s*:\s*"([^"]+)"'),
        ],
        "ssrf_endpoints": [
            {
                "path": "/artifactory/api/remote",
                "method": "POST",
                "vector": "Remote repository creation can point to internal proxy URLs",
            },
            {
                "path": "/artifactory/api/system/licenses",
                "method": "POST",
                "vector": "License validation can trigger server-side HTTP requests",
            },
        ],
    },
}


def _detect_app(
    response_body: str, headers: dict[str, str], app_name: str
) -> dict[str, Any] | None:
    """Check if a response matches an application fingerprint."""
    sig = APP_SIGNATURES.get(app_name)
    if not sig:
        return None

    combined = response_body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    matches = sum(1 for pat in sig["patterns"] if pat.search(combined))

    if matches == 0:
        return None

    version = "unknown"
    for vp in sig.get("version_patterns", []):
        m = vp.search(combined)
        if m:
            if m.lastindex:
                version = m.group(1)
            else:
                version = m.group(0)
            break

    return {
        "app": app_name,
        "confidence": min(matches / len(sig["patterns"]), 1.0),
        "version": version,
        "ssrf_endpoints": sig["ssrf_endpoints"],
    }


def detect_app_ssrf(
    response_body: str,
    response_headers: dict[str, str],
    url: str = "",
) -> list[dict[str, Any]]:
    """Scan a response for application fingerprints and return SSRF endpoints.

    Args:
        response_body: The response body text.
        response_headers: Response headers as a flat dict.
        url: The URL that produced the response.

    Returns:
        List of detection results with SSRF-prone endpoints.
    """
    findings: list[dict[str, Any]] = []

    for app_name in APP_SIGNATURES:
        result = _detect_app(response_body, response_headers, app_name)
        if result:
            findings.append(
                {
                    "type": "app_ssrf_vector",
                    "app": result["app"],
                    "version": result["version"],
                    "confidence": result["confidence"],
                    "url": url,
                    "findings": [
                        {
                            "path": ep["path"],
                            "method": ep["method"],
                            "vector": ep["vector"],
                        }
                        for ep in result["ssrf_endpoints"]
                    ],
                }
            )

    findings.sort(key=lambda f: (-f["confidence"], f["app"]))
    return findings


def scan_responses(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Batch-scan multiple responses for application SSRF vectors.

    Args:
        responses: List of dicts with keys: url, body, headers.

    Returns:
        All detections across all responses.
    """
    all_findings: list[dict[str, Any]] = []

    for resp in responses:
        url = resp.get("url", "")
        body = str(resp.get("body", "") or resp.get("body_text", "") or "")
        headers = resp.get("headers", {})

        findings = detect_app_ssrf(body, headers, url)
        all_findings.extend(findings)

    return all_findings
