"""VirusTotal API v3 integration for file, URL, IP, and domain intelligence.

Provides threat reputation lookups against VirusTotal's database including
malware detection results, community scores, WHOIS data, and related
indicators of compromise.

Environment Variables:
    VT_API_KEY: VirusTotal API key (required).

Usage:
    from src.intelligence.feeds.virustotal import VirusTotalClient, VirusTotalConfig

    config = VirusTotalConfig(api_key="...")
    async with VirusTotalClient(config) as client:
        report = await client.get_ip_report("1.1.1.1")
        print(report.verdict)
"""

import logging
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from src.intelligence.feeds.base import BaseFeedConnector, FeedConfig

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalConfig(FeedConfig):
    """Configuration for the VirusTotal API connector.

    Attributes:
        api_key: VirusTotal API key.
        base_url: VirusTotal API base URL.
        timeout_seconds: Request timeout.
        max_retries: Maximum retry attempts.
    """

    api_key: str = Field(..., min_length=1)
    base_url: str = Field(default=VT_BASE_URL)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)


class VirusTotalVerdict(StrEnum):
    """Aggregated verdict from VirusTotal analysis.

    Values:
        MALICIOUS: Detected as malicious by multiple engines.
        SUSPICIOUS: Flagged as suspicious but not confirmed malicious.
        HARMLESS: No detection across engines.
        UNDETECTED: Insufficient data for a verdict.
        TIMEOUT: Analysis timed out.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNDETECTED = "undetected"
    TIMEOUT = "timeout"


class VirusTotalReport(BaseModel):
    """Standardized VirusTotal analysis report.

    Attributes:
        id: VirusTotal report identifier.
        type: Object type (ip_address, domain, url, file).
        verdict: Aggregated threat verdict.
        malicious_count: Number of engines flagging as malicious.
        suspicious_count: Number of engines flagging as suspicious.
        harmless_count: Number of engines flagging as harmless.
        undetected_count: Number of engines with no detection.
        last_analysis_date: Timestamp of the last analysis.
        reputation: Community reputation score.
        tags: List of threat tags assigned by VirusTotal.
        raw_data: Raw API response data for advanced use.
    """

    id: str
    type: str
    verdict: VirusTotalVerdict
    malicious_count: int = Field(default=0, ge=0)
    suspicious_count: int = Field(default=0, ge=0)
    harmless_count: int = Field(default=0, ge=0)
    undetected_count: int = Field(default=0, ge=0)
    last_analysis_date: datetime | None = Field(default=None)
    reputation: int = Field(default=0)
    tags: list[str] = Field(default_factory=list)
    categories: dict[str, str] = Field(default_factory=dict)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class VirusTotalClient(BaseFeedConnector):
    """VirusTotal API v3 client for threat intelligence lookups.

    Supports IP addresses, domains, URLs, and file hash lookups with
    standardized report parsing and verdict aggregation.

    Attributes:
        config: VirusTotal configuration.
    """

    def __init__(self, config: VirusTotalConfig) -> None:
        headers = {"x-apikey": config.api_key}
        merged_headers = {**config.extra_headers, **headers}
        full_config = FeedConfig(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            verify_ssl=config.verify_ssl,
            user_agent=config.user_agent,
            extra_headers=merged_headers,
        )
        super().__init__(full_config)
        self._vt_config = config

    @property
    def client_name(self) -> str:
        return "VirusTotal"

    async def get_ip_report(self, ip_address: str) -> VirusTotalReport:
        """Retrieve threat intelligence for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address to look up.

        Returns:
            Parsed VirusTotalReport for the IP address.

        Raises:
            FeedError: If the request fails or IP is invalid.
        """
        response = await self._get(f"/ip_addresses/{ip_address}")
        if response.status_code == 404:
            return VirusTotalReport(
                id=ip_address,
                type="ip_address",
                verdict=VirusTotalVerdict.UNDETECTED,
                raw_data={"error": "IP not found"},
            )
        response.raise_for_status()
        return self._parse_report(response.json(), "ip_address")

    async def get_domain_report(self, domain: str) -> VirusTotalReport:
        """Retrieve threat intelligence for a domain.

        Args:
            domain: Domain name to look up.

        Returns:
            Parsed VirusTotalReport for the domain.
        """
        response = await self._get(f"/domains/{domain}")
        if response.status_code == 404:
            return VirusTotalReport(
                id=domain,
                type="domain",
                verdict=VirusTotalVerdict.UNDETECTED,
                raw_data={"error": "Domain not found"},
            )
        response.raise_for_status()
        return self._parse_report(response.json(), "domain")

    async def get_url_report(self, url: str) -> VirusTotalReport:
        """Retrieve threat intelligence for a URL.

        Args:
            url: URL to look up.

        Returns:
            Parsed VirusTotalReport for the URL.
        """
        import base64

        encoded_url = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
        response = await self._get(f"/urls/{encoded_url}")
        if response.status_code == 404:
            return VirusTotalReport(
                id=url,
                type="url",
                verdict=VirusTotalVerdict.UNDETECTED,
                raw_data={"error": "URL not found"},
            )
        response.raise_for_status()
        return self._parse_report(response.json(), "url")

    async def get_file_report(self, file_hash: str) -> VirusTotalReport:
        """Retrieve threat intelligence for a file by its hash.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of the file.

        Returns:
            Parsed VirusTotalReport for the file.
        """
        response = await self._get(f"/files/{file_hash}")
        if response.status_code == 404:
            return VirusTotalReport(
                id=file_hash,
                type="file",
                verdict=VirusTotalVerdict.UNDETECTED,
                raw_data={"error": "File hash not found"},
            )
        response.raise_for_status()
        return self._parse_report(response.json(), "file")

    async def get_domain_subdomains(self, domain: str) -> list[str]:
        """Retrieve subdomains for a given domain.

        Args:
            domain: Parent domain to enumerate.

        Returns:
            List of subdomain strings.
        """
        response = await self._get(f"/domains/{domain}/subdomains")
        response.raise_for_status()
        data = response.json()
        subdomains: list[str] = []
        for item in data.get("data", []):
            subdomain_id = item.get("id", "")
            if subdomain_id:
                subdomains.append(subdomain_id)
        return subdomains

    async def get_domain_resolutions(self, domain: str) -> list[dict[str, Any]]:
        """Retrieve DNS resolution history for a domain.

        Args:
            domain: Domain to look up.

        Returns:
            List of resolution records with IP and timestamp.
        """
        response = await self._get(f"/domains/{domain}/resolutions")
        response.raise_for_status()
        data = response.json()
        resolutions: list[dict[str, Any]] = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            resolutions.append(
                {
                    "ip_address": attrs.get("ip_address", ""),
                    "date": attrs.get("date"),
                }
            )
        return resolutions

    async def get_ip_resolutions(self, ip_address: str) -> list[dict[str, Any]]:
        """Retrieve domains that have resolved to a given IP.

        Args:
            ip_address: IP address to look up.

        Returns:
            List of resolution records with domain and timestamp.
        """
        response = await self._get(f"/ip_addresses/{ip_address}/resolutions")
        response.raise_for_status()
        data = response.json()
        resolutions: list[dict[str, Any]] = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            resolutions.append(
                {
                    "host_name": attrs.get("host_name", ""),
                    "date": attrs.get("date"),
                }
            )
        return resolutions

    async def get_ip_communicating_files(self, ip_address: str) -> list[dict[str, Any]]:
        """Retrieve files that have communicated with an IP address.

        Args:
            ip_address: IP address to look up.

        Returns:
            List of file records with hash and detection counts.
        """
        response = await self._get(f"/ip_addresses/{ip_address}/communicating_files")
        response.raise_for_status()
        data = response.json()
        files: list[dict[str, Any]] = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            files.append(
                {
                    "sha256": attrs.get("sha256", ""),
                    "sha1": attrs.get("sha1", ""),
                    "md5": attrs.get("md5", ""),
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                }
            )
        return files

    def _parse_report(self, data: dict[str, Any], obj_type: str) -> VirusTotalReport:
        """Parse a VirusTotal API response into a standardized report.

        Args:
            data: Raw API response JSON.
            obj_type: Object type identifier.

        Returns:
            Parsed VirusTotalReport instance.
        """
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious >= 3:
            verdict = VirusTotalVerdict.MALICIOUS
        elif malicious >= 1 or suspicious >= 2:
            verdict = VirusTotalVerdict.SUSPICIOUS
        elif harmless > 0 and malicious == 0 and suspicious == 0:
            verdict = VirusTotalVerdict.HARMLESS
        else:
            verdict = VirusTotalVerdict.UNDETECTED

        analysis_date = None
        last_analysis_date = attributes.get("last_analysis_date")
        if last_analysis_date is not None:
            analysis_date = datetime.fromtimestamp(last_analysis_date)

        return VirusTotalReport(
            id=data.get("data", {}).get("id", ""),
            type=obj_type,
            verdict=verdict,
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            undetected_count=undetected,
            last_analysis_date=analysis_date,
            reputation=attributes.get("reputation", 0),
            tags=attributes.get("tags", []),
            categories=attributes.get("categories", {}),
            raw_data=data,
        )
