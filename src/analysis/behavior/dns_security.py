"""DNS security analysis.

Analyzes DNS-related security issues including:
- Missing or weak SPF records
- Missing DKIM configuration
- Missing DMARC policy
- DNS misconfigurations
- Subdomain takeover potential
- DNSSEC status
"""

from typing import Any

from src.core.plugins import register_plugin

ENRICHMENT_PROVIDER = "enrichment_provider"


@register_plugin(ENRICHMENT_PROVIDER, "dns_security")
def dns_security_analyzer(
    domains: list[str], dns_records: dict[str, dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Analyze DNS security configuration for domains.

    Args:
        domains: List of domain names to analyze.
        dns_records: Optional dict of domain -> DNS records.
            If not provided, analysis is based on domain patterns only.

    Returns:
        List of DNS security finding dicts.
    """
    findings: list[dict[str, Any]] = []

    for domain in domains:
        domain = domain.strip().lower()
        if not domain:
            continue

        # Remove wildcards and protocol prefixes
        if domain.startswith("*."):
            domain = domain[2:]
        if "://" in domain:
            domain = domain.split("://", 1)[1].split("/", 1)[0]

        issues: list[str] = []
        severity = "low"
        evidence: dict[str, Any] = {"domain": domain}

        records = (dns_records or {}).get(domain, {})

        # Check SPF record
        spf_record = records.get("spf", "")
        if not spf_record:
            issues.append("missing_spf_record")
            severity = "medium"
        else:
            spf_lower = spf_record.lower()
            if "+all" in spf_lower:
                issues.append("spf_allows_any")
                severity = "high"
            elif "?all" in spf_lower:
                issues.append("spf_neutral_all")
                if severity == "low":
                    severity = "medium"
            elif "~all" in spf_lower:
                issues.append("spf_softfail")
                if severity == "low":
                    severity = "medium"
            elif "-all" not in spf_lower:
                issues.append("spf_missing_hardfail")
                if severity == "low":
                    severity = "medium"

        # Check DKIM record
        dkim_record = records.get("dkim", "")
        if not dkim_record:
            issues.append("missing_dkim_record")
            if severity == "low":
                severity = "medium"

        # Check DMARC record
        dmarc_record = records.get("dmarc", "")
        if not dmarc_record:
            issues.append("missing_dmarc_record")
            severity = "high" if severity != "critical" else severity
        else:
            dmarc_lower = dmarc_record.lower()
            if "p=none" in dmarc_lower:
                issues.append("dmarc_policy_none")
                if severity == "low":
                    severity = "medium"
            elif "p=quarantine" in dmarc_lower:
                issues.append("dmarc_policy_quarantine")
                if severity == "low":
                    severity = "medium"
            # Check for DMARC alignment mode
            if "aspf=r" in dmarc_lower:
                issues.append("dmarc_relaxed_spf_alignment")
            if "adkim=r" in dmarc_lower:
                issues.append("dmarc_relaxed_dkim_alignment")
            # Check for DMARC reporting
            if "rua=" not in dmarc_lower:
                issues.append("dmarc_missing_aggregate_report")
            if "ruf=" not in dmarc_lower:
                issues.append("dmarc_missing_forensic_report")

        # Check DNSSEC
        dnssec = records.get("dnssec", False)
        if not dnssec:
            issues.append("dnssec_not_enabled")
            if severity == "low":
                severity = "medium"

        # Check for CNAME flattening (potential subdomain takeover)
        cname = records.get("cname", "")
        if cname:
            # Check for dangling CNAME (points to non-existent service)
            takeover_services = {
                ".github.io": "GitHub Pages",
                ".herokuapp.com": "Heroku",
                ".s3.amazonaws.com": "AWS S3",
                ".s3-website": "AWS S3 Website",
                ".azurewebsites.net": "Azure",
                ".cloudfront.net": "CloudFront",
                ".c.storage.googleapis.com": "Google Cloud Storage",
                ".storage.googleapis.com": "Google Cloud Storage",
                ".surge.sh": "Surge",
                ".bitbucket.io": "Bitbucket",
                ".myshopify.com": "Shopify",
                ".wordpress.com": "WordPress",
                ".ghost.io": "Ghost",
                ".readthedocs.io": "ReadTheDocs",
                ".netlify.app": "Netlify",
                ".vercel.app": "Vercel",
                ".firebaseapp.com": "Firebase",
                ".elasticbeanstalk.com": "AWS Elastic Beanstalk",
                ".pantheonsite.io": "Pantheon",
                ".teamwork.com": "Teamwork",
                ".helpscoutdocs.com": "Help Scout",
                ".statuspage.io": "Statuspage",
                ".uservoice.com": "UserVoice",
                ".thinkific.com": "Thinkific",
                ".mystrikingly.com": "Strikingly",
                ".tumblr.com": "Tumblr",
                ".amazonaws.com": "AWS (generic)",
                ".digitaloceanspaces.com": "DigitalOcean Spaces",
                ".cdn77.net": "CDN77",
                ".fastly.net": "Fastly",
            }
            for service, name in takeover_services.items():
                if service in cname.lower():
                    issues.append(f"potential_subdomain_takeover:{name}")
                    severity = "high" if severity != "critical" else severity
                    evidence["takeover_service"] = name
                    evidence["cname_target"] = cname
                    break

        # Check for wildcard DNS (potential security risk)
        if records.get("wildcard", False):
            issues.append("wildcard_dns_enabled")
            if severity == "low":
                severity = "medium"

        # Check for missing MX record (email delivery issues)
        mx_records = records.get("mx", [])
        if not mx_records and ("mail." in domain or "email" in domain):
            issues.append("missing_mx_record")
            if severity == "low":
                severity = "medium"

        # Check for DNS zone transfer indicators
        if records.get("axfr_enabled", False):
            issues.append("dns_zone_transfer_enabled")
            severity = "high" if severity != "critical" else severity

        # Check for missing reverse DNS
        if not records.get("ptr", "") and records.get("ip", ""):
            issues.append("missing_reverse_dns")
            if severity == "low":
                severity = "medium"

        # Check for wildcard DNS (potential security risk)
        if records.get("wildcard", False):
            issues.append("wildcard_dns_enabled")
            if severity == "low":
                severity = "medium"

        if issues:
            findings.append(
                {
                    "url": f"dns:{domain}",
                    "endpoint_key": f"dns:{domain}",
                    "endpoint_base_key": domain,
                    "endpoint_type": "DNS",
                    "issues": sorted(issues),
                    "severity": severity,
                    "confidence": 0.90,
                    "category": "dns_security",
                    "title": f"DNS security issue: {issues[0]}",
                    "evidence": evidence,
                }
            )

    findings.sort(
        key=lambda item: (
            0 if item["severity"] in ("critical", "high") else 1,
            -len(item["issues"]),
            item["url"],
        )
    )
    return findings[:50]
