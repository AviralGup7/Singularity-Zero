"""DNS record enumeration for recon pipeline.

Enumerates DNS records (MX, NS, TXT, SOA, A, AAAA, CNAME, SRV) for
discovered domains and subdomains. This reveals:
- Email infrastructure (MX records)
- DNS delegation and potential zone transfers (NS)
- SPF/DKIM/DMARC and other security TXT records
- Infrastructure footprint (A/AAAA)
- Service discovery (SRV records)
"""

import asyncio
import logging
import socket
from typing import Any

from src.pipeline.services.tool_execution import CompletedToolRun, ToolInvocation, run_external_tool

logger = logging.getLogger(__name__)

# Security-relevant TXT record patterns
SPF_PREFIX = "v=spf1"
DKIM_PREFIX = "v=DKIM1"
DMARC_PREFIX = "v=DMARC1"
GOOGLE_SITE_VERIFICATION = "google-site-verification"
MS_VERIFICATION = "MS=ms"


async def enumerate_dns_records(
    domains: set[str],
    record_types: list[str] | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Enumerate DNS records for a set of domains.

    Args:
        domains: Set of domain names to enumerate.
        record_types: List of record types. Defaults to all common types.
        timeout: Per-query timeout in seconds.

    Returns:
        List of record dicts with keys: domain, record_type, value,
        security_relevant, details.
    """
    if not domains:
        return []

    if record_types is None:
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV"]

    results: list[dict[str, Any]] = []

    for domain in sorted(domains):
        for rtype in record_types:
            found = await _query_dns(domain, rtype, timeout)
            for value in found:
                is_security = _is_security_relevant(rtype, value)
                details = _extract_details(rtype, value)
                results.append(
                    {
                        "domain": domain,
                        "record_type": rtype,
                        "value": value,
                        "security_relevant": is_security,
                        "details": details,
                    }
                )

    logger.info(
        "DNS enumeration: queried %d domains × %d types, found %d records",
        len(domains),
        len(record_types),
        len(results),
    )
    return results


async def _query_dns(
    domain: str,
    record_type: str,
    timeout: float,
) -> list[str]:
    """Query DNS for a specific record type using asyncio DNS resolver."""
    values: list[str] = []

    try:
        # Fix Audit #20: Use get_running_loop
        loop = asyncio.get_running_loop()

        if record_type == "A":
            addrs = await loop.run_in_executor(None, _resolve_a, domain)
            values.extend(addrs)
        elif record_type == "AAAA":
            addrs = await loop.run_in_executor(None, _resolve_aaaa, domain)
            values.extend(addrs)
        elif record_type in ("CNAME", "NS", "MX", "TXT", "SOA", "SRV"):
            # Use nslookup via run_external_tool for these types
            addrs = await _resolve_generic(domain, record_type)
            values.extend(addrs)

    except (TimeoutError, socket.gaierror, socket.herror, OSError) as exc:
        logger.debug("DNS query for %s %s failed: %s", domain, record_type, exc)

    return values


def _resolve_a(domain: str) -> list[str]:
    """Resolve A records."""
    try:
        return [str(addr[4][0]) for addr in socket.getaddrinfo(domain, None, socket.AF_INET)]
    except socket.gaierror:
        return []


def _resolve_aaaa(domain: str) -> list[str]:
    """Resolve AAAA records."""
    try:
        return [str(addr[4][0]) for addr in socket.getaddrinfo(domain, None, socket.AF_INET6)]
    except socket.gaierror:
        return []


async def _resolve_generic(domain: str, record_type: str) -> list[str]:
    """Generic resolution using nslookup via run_external_tool."""
    try:
        result = await _run_nslookup(domain, record_type)
        if result.timed_out or not result.ok:
            return []
        return _parse_nslookup_output(result.stdout, record_type)
    except Exception as exc:
        logger.debug("nslookup failed for %s %s: %s", domain, record_type, exc)
        return []


def _parse_nslookup_output(output: str, record_type: str) -> list[str]:
    """Parse nslookup output for a specific record type."""
    values: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if record_type == "MX" and "mail exchanger" in line.lower():
            values.append(line.split("mail exchanger =")[-1].strip())
        elif record_type == "NS" and line.startswith("nameserver"):
            values.append(line.split("nameserver =")[-1].strip())
        elif record_type == "TXT" and ('"' in line or line.startswith("text")):
            text = line.split("text =")[-1].strip().strip('"')
            if text:
                values.append(text)
        elif record_type == "SOA" and "serial" in line.lower():
            values.append(line)
        elif record_type == "CNAME" and "canonical name" in line.lower():
            values.append(line.split("canonical name =")[-1].strip())
        elif record_type == "SRV" and "sv service" in line.lower():
            values.append(line)
        else:
            parts = line.split()
            if len(parts) >= 2:
                candidate = parts[-1].rstrip(".")
                if any(c.isalpha() for c in candidate):
                    values.append(candidate)
    return values


async def _run_nslookup(domain: str, record_type: str) -> CompletedToolRun:
    """Run nslookup asynchronously via the canonical tool runner."""
    invocation = ToolInvocation(
        tool_name="nslookup",
        args=[f"-type={record_type}", domain],
        timeout_seconds=5,
    )
    return await run_external_tool(invocation)


def _is_security_relevant(record_type: str, value: str) -> bool:
    """Determine if a DNS record has security implications."""
    if record_type == "TXT":
        value_lower = value.lower()
        return any(
            prefix in value_lower
            for prefix in [
                "spf",
                "dkim",
                "dmarc",
                "_amazonses",
                "google-site-verification",
                "facebook-domain-verification",
                "apple-domain-verification",
            ]
        )
    if record_type == "MX":
        return True  # Email infrastructure is always security-relevant
    if record_type == "NS":
        return True  # DNS delegation is security-relevant
    if record_type == "SRV":
        return True  # Service discovery reveals infrastructure
    return False


def _extract_details(record_type: str, value: str) -> dict[str, Any]:
    """Extract structured details from a DNS record value."""
    details: dict[str, Any] = {"raw": value}

    if record_type == "TXT":
        if value.startswith("v=spf1"):
            details["record"] = "SPF"
            details["mechanisms"] = value.split()
        elif value.startswith("v=DMARC1"):
            details["record"] = "DMARC"
            for part in value.split(";"):
                if "=" in part:
                    key, val = part.strip().split("=", 1)
                    details[key.strip().lower()] = val.strip()
        elif value.startswith("v=DKIM1"):
            details["record"] = "DKIM"
        elif value.startswith("google-site-verification"):
            details["record"] = "Google Verification"
            details["token"] = value.split("=")[-1] if "=" in value else value
    elif record_type == "MX":
        parts = value.split()
        if len(parts) >= 2:
            details["priority"] = parts[0]
            details["mail_server"] = parts[-1].rstrip(".")
    elif record_type == "SOA":
        details["record"] = "SOA"
    elif record_type == "A":
        details["record"] = "A"
        details["ip"] = value
    elif record_type == "AAAA":
        details["record"] = "AAAA"
        details["ipv6"] = value

    return details


def build_dns_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a structured DNS report from enumeration results.

    Args:
        records: DNS record dicts from enumerate_dns_records.

    Returns:
        Report dict with per-domain breakdown, security findings,
        and summary statistics.
    """
    by_domain: dict[str, list[dict[str, Any]]] = {}
    security_findings: list[dict[str, Any]] = []
    type_counts: dict[str, int] = {}

    for record in records:
        domain = record["domain"]
        by_domain.setdefault(domain, []).append(record)
        rtype = record["record_type"]
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

        if record.get("security_relevant"):
            security_findings.append(
                {
                    "domain": domain,
                    "type": rtype,
                    "finding": record.get("details", {}).get(
                        "record", f"Security-relevant {rtype}"
                    ),
                    "details": record.get("details"),
                }
            )

    # Check for missing security records
    security_checks = _check_dns_security(by_domain)

    return {
        "domains_queried": len(by_domain),
        "total_records": len(records),
        "record_type_counts": type_counts,
        "security_findings": security_findings,
        "security_checks": security_checks,
        "by_domain": by_domain,
    }


def _check_dns_security(by_domain: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Check for missing DNS security configurations."""
    findings: list[dict[str, Any]] = []

    for domain, records in by_domain.items():
        txt_records = [r for r in records if r["record_type"] == "TXT"]
        mx_records = [r for r in records if r["record_type"] == "MX"]

        # Check SPF
        has_spf = any(r.get("details", {}).get("record") == "SPF" for r in txt_records)
        if not has_spf and mx_records:
            findings.append(
                {
                    "domain": domain,
                    "issue": "missing_spf",
                    "severity": "medium",
                    "description": f"Domain {domain} has MX records but no SPF record. This may allow email spoofing.",
                }
            )

        # Check DMARC
        has_dmarc = any(r.get("details", {}).get("record") == "DMARC" for r in txt_records)
        if not has_dmarc:
            findings.append(
                {
                    "domain": domain,
                    "issue": "missing_dmarc",
                    "severity": "low",
                    "description": f"Domain {domain} has no DMARC record. Email authentication policy is not enforced.",
                }
            )

    return findings
