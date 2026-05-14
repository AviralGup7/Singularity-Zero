"""Technology fingerprinting and summary builder.

Contains the build_technology_summary function for analyzing response headers
and bodies to identify technologies, frameworks, and services with security
implications.
Extracted from intelligence_insights.py for better separation of concerns.
"""

from typing import Any


def build_technology_summary(
    analysis_results: dict[str, list[dict[str, Any]]], responses: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Build a comprehensive technology fingerprinting summary."""
    counts: dict[str, dict[str, Any]] = {}
    for item in analysis_results.get("technology_fingerprint", []):
        label = str(item.get("technology", "")).strip()
        if label:
            if label not in counts:
                counts[label] = {
                    "technology": label,
                    "count": 0,
                    "category": "unknown",
                    "security_implications": [],
                }
            counts[label]["count"] += 1
    if responses:
        header_tech_patterns = {
            "x-powered-by": {
                "Express": "express",
                "ASP.NET": "aspnet",
                "PHP": "php",
                "Next.js": "nextjs",
            },
            "server": {
                "nginx": "nginx",
                "Apache": "apache",
                "Cloudflare": "cloudflare",
                "AWS": "aws",
                "Google": "google",
                "Microsoft-IIS": "iis",
            },
            "x-aspnet-version": {"ASP.NET": "aspnet"},
            "x-generator": {"WordPress": "wordpress", "Drupal": "drupal", "Joomla": "joomla"},
            "x-drupal-cache": {"Drupal": "drupal"},
            "x-wix-request-id": {"Wix": "wix"},
            "x-shopid": {"Shopify": "shopify"},
            "x-content-type-options": {"Security Header": "security_header"},
            "strict-transport-security": {"HSTS": "hsts"},
            "content-security-policy": {"CSP": "csp"},
        }
        body_tech_patterns = {
            "__next": "nextjs",
            "wp-content": "wordpress",
            "wp-includes": "wordpress",
            "drupalSettings": "drupal",
            "angular.js": "angular",
            "react": "react",
            "vue.js": "vue",
            "jquery": "jquery",
            "bootstrap": "bootstrap",
            "laravel": "laravel",
            "django": "django",
            "rails": "rails",
            "spring": "spring",
            "grafana": "grafana",
            "kibana": "kibana",
            "jenkins": "jenkins",
            "swagger": "swagger",
            "graphql": "graphql",
        }
        security_implications = {
            "express": ["Known CVEs for specific versions", "Default error pages may leak info"],
            "aspnet": ["ViewState MAC bypass potential", "Debug mode may be enabled"],
            "php": ["Version disclosure risk", "Error reporting may leak paths"],
            "nginx": ["Misconfiguration may allow path traversal", "Version disclosure"],
            "apache": [".htaccess bypass potential", "Version disclosure"],
            "wordpress": ["Plugin vulnerability surface", "Default admin paths"],
            "drupal": ["Module vulnerability surface", "REST endpoint exposure"],
            "grafana": ["Default credentials", "SSRF via data sources"],
            "kibana": ["Remote code execution CVEs", "Authentication bypass"],
            "jenkins": ["Script console exposure", "Default credentials"],
            "swagger": ["API surface exposure", "Undocumented endpoints"],
            "graphql": ["Introspection exposure", "Batch query abuse"],
            "security_header": ["Positive security indicator"],
            "hsts": ["Positive security indicator"],
            "csp": ["Positive security indicator"],
        }
        for response in responses:
            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
            body = str(response.get("body_text", "")).lower()
            for header, patterns in header_tech_patterns.items():
                if header in headers:
                    header_value = headers[header].lower()
                    for tech_name, tech_id in patterns.items():
                        if tech_name.lower() in header_value:
                            if tech_id not in counts:
                                counts[tech_id] = {
                                    "technology": tech_name,
                                    "count": 0,
                                    "category": "framework"
                                    if tech_id
                                    in {
                                        "express",
                                        "aspnet",
                                        "php",
                                        "nextjs",
                                        "django",
                                        "rails",
                                        "spring",
                                    }
                                    else "server"
                                    if tech_id in {"nginx", "apache", "iis"}
                                    else "security"
                                    if tech_id in {"security_header", "hsts", "csp"}
                                    else "service",
                                    "security_implications": security_implications.get(tech_id, []),
                                }
                            counts[tech_id]["count"] += 1
            for pattern, tech_id in body_tech_patterns.items():
                if pattern in body:
                    tech_name = pattern.replace(".js", "").replace("-", " ").title()
                    if tech_id not in counts:
                        counts[tech_id] = {
                            "technology": tech_name,
                            "count": 0,
                            "category": "library"
                            if tech_id in {"jquery", "bootstrap", "react", "vue", "angular"}
                            else "framework"
                            if tech_id
                            in {
                                "nextjs",
                                "wordpress",
                                "drupal",
                                "laravel",
                                "django",
                                "rails",
                                "spring",
                            }
                            else "service"
                            if tech_id in {"grafana", "kibana", "jenkins", "swagger", "graphql"}
                            else "unknown",
                            "security_implications": security_implications.get(tech_id, []),
                        }
                    counts[tech_id]["count"] += 1
    summary = list(counts.values())
    summary.sort(key=lambda item: (-item["count"], item["technology"]))
    return summary[:20]
