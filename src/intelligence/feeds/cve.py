"""CVE (Common Vulnerabilities and Exposures) database synchronization.

Provides access to the NIST NVD CVE API for vulnerability lookups,
CVSS scoring, affected product enumeration, and change tracking
for vulnerability intelligence.

Environment Variables:
    NVD_API_KEY: NVD API key (optional, increases rate limit).

Usage:
    from src.intelligence.feeds.cve import CVESyncClient, CVEConfig

    config = CVEConfig()
    async with CVESyncClient(config) as client:
        cve = await client.get_cve("CVE-2024-0001")
        print(cve.cvss_score, cve.severity)
"""

import logging
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from src.intelligence.feeds.base import BaseFeedConnector, FeedConfig

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVESeverity(StrEnum):
    """CVSS v3 severity rating.

    Values:
        CRITICAL: CVSS score 9.0-10.0
        HIGH: CVSS score 7.0-8.9
        MEDIUM: CVSS score 4.0-6.9
        LOW: CVSS score 0.1-3.9
        NONE: CVSS score 0.0
        UNKNOWN: No CVSS score available
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class CVEAffectedProduct(BaseModel):
    """A product affected by a CVE.

    Attributes:
        vendor: Product vendor name.
        product: Product name.
        version: Affected version string or range.
        cpe: Common Platform Enumeration identifier.
    """

    vendor: str = Field(default="")
    product: str = Field(default="")
    version: str = Field(default="")
    cpe: str = Field(default="")


class CVEEntry(BaseModel):
    """Standardized CVE vulnerability entry.

    Attributes:
        cve_id: CVE identifier (e.g., CVE-2024-0001).
        description: Vulnerability description text.
        severity: CVSS v3 severity rating.
        cvss_score: CVSS v3 base score (0.0-10.0).
        cvss_vector: CVSS v3 vector string.
        published_date: When the CVE was first published.
        last_modified: Last modification timestamp.
        references: List of reference URLs.
        affected_products: List of affected vendor/product combinations.
        weaknesses: List of CWE identifiers.
        source: Data source identifier.
        raw_data: Raw API response data.
    """

    cve_id: str
    description: str = Field(default="")
    severity: CVESeverity = Field(default=CVESeverity.UNKNOWN)
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = Field(default="")
    published_date: datetime | None = Field(default=None)
    last_modified: datetime | None = Field(default=None)
    references: list[str] = Field(default_factory=list)
    affected_products: list[CVEAffectedProduct] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)
    source: str = Field(default="NVD")
    raw_data: dict[str, Any] = Field(default_factory=dict)


class CVESearchResult(BaseModel):
    """Result from a CVE search query.

    Attributes:
        total_results: Total number of matching CVEs.
        entries: List of CVE entries on the current page.
    """

    total_results: int = Field(default=0, ge=0)
    entries: list[CVEEntry] = Field(default_factory=list)


class CVEConfig(FeedConfig):
    """Configuration for the CVE/NVD API connector.

    Attributes:
        api_key: NVD API key (optional but recommended).
        base_url: NVD API base URL.
        timeout_seconds: Request timeout.
        max_retries: Maximum retry attempts.
    """

    api_key: str = Field(default="")
    base_url: str = Field(default="https://services.nvd.nist.gov/rest/json")
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)


class CVESyncClient(BaseFeedConnector):
    """NIST NVD CVE API client for vulnerability intelligence.

    Provides CVE lookups, keyword searches, date-range queries,
    and change tracking through the NVD REST API.

    Attributes:
        config: CVE configuration.
    """

    def __init__(self, config: CVEConfig) -> None:
        headers: dict[str, str] = {}
        if config.api_key:
            headers["apiKey"] = config.api_key
        merged_headers = {**config.extra_headers, **headers}
        full_config = FeedConfig(
            api_key=config.api_key or "anonymous",
            base_url=config.base_url,
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            verify_ssl=config.verify_ssl,
            user_agent=config.user_agent,
            extra_headers=merged_headers,
        )
        super().__init__(full_config)
        self._cve_config = config

    @property
    def client_name(self) -> str:
        return "NVD CVE"

    async def get_cve(self, cve_id: str) -> CVEEntry | None:
        """Retrieve details for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-0001").

        Returns:
            CVEEntry if found, None otherwise.
        """
        response = await self._get(
            "/cves/2.0",
            params={"cveId": cve_id},
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        results = data.get("vulnerabilities", [])
        if not results:
            return None
        return self._parse_cve(results[0])

    async def search_cves(
        self,
        keyword: str | None = None,
        cve_id: str | None = None,
        cvss_v3_metrics: str | None = None,
        severity: str | None = None,
        pub_start_date: datetime | None = None,
        pub_end_date: datetime | None = None,
        mod_start_date: datetime | None = None,
        mod_end_date: datetime | None = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> CVESearchResult:
        """Search the CVE database with multiple filter criteria.

        Args:
            keyword: Free-text keyword search across descriptions.
            cve_id: Specific CVE ID to filter.
            cvss_v3_metrics: CVSS v3 vector string filter.
            severity: Severity filter (CRITICAL, HIGH, MEDIUM, LOW).
            pub_start_date: Publication date range start.
            pub_end_date: Publication date range end.
            mod_start_date: Modification date range start.
            mod_end_date: Modification date range end.
            results_per_page: Number of results per page (max 2000).
            start_index: Starting index for pagination.

        Returns:
            CVESearchResult with matching CVE entries.
        """
        params: dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }

        if keyword:
            params["keywordSearch"] = keyword
        if cve_id:
            params["cveId"] = cve_id
        if cvss_v3_metrics:
            params["cvssV3Metrics"] = cvss_v3_metrics
        if severity:
            params["severity"] = severity
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if mod_start_date:
            params["lastModStartDate"] = mod_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if mod_end_date:
            params["lastModEndDate"] = mod_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        response = await self._get("/cves/2.0", params=params)
        response.raise_for_status()
        return self._parse_search_result(response.json())

    async def search_by_cpe(
        self,
        cpe_match_string: str,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> CVESearchResult:
        """Search CVEs by CPE (Common Platform Enumeration) string.

        Args:
            cpe_match_string: CPE 2.3 match string (e.g., "cpe:2.3:a:apache:log4j").
            results_per_page: Number of results per page.
            start_index: Starting index for pagination.

        Returns:
            CVESearchResult with matching CVE entries.
        """
        response = await self._get(
            "/cves/2.0",
            params={
                "cpeName": cpe_match_string,
                "resultsPerPage": min(results_per_page, 2000),
                "startIndex": start_index,
            },
        )
        response.raise_for_status()
        return self._parse_search_result(response.json())

    async def get_cve_changes(
        self,
        mod_start_date: datetime,
        mod_end_date: datetime,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> CVESearchResult:
        """Retrieve CVEs modified within a date range.

        Args:
            mod_start_date: Start of modification date range.
            mod_end_date: End of modification date range.
            results_per_page: Number of results per page.
            start_index: Starting index for pagination.

        Returns:
            CVESearchResult with modified CVE entries.
        """
        response = await self._get(
            "/cves/2.0",
            params={
                "lastModStartDate": mod_start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": mod_end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": min(results_per_page, 2000),
                "startIndex": start_index,
            },
        )
        response.raise_for_status()
        return self._parse_search_result(response.json())

    async def get_cve_count(
        self,
        keyword: str | None = None,
        pub_start_date: datetime | None = None,
        pub_end_date: datetime | None = None,
    ) -> int:
        """Get the count of CVEs matching criteria.

        Args:
            keyword: Free-text keyword filter.
            pub_start_date: Publication date range start.
            pub_end_date: Publication date range end.

        Returns:
            Total number of matching CVEs.
        """
        params: dict[str, Any] = {}
        if keyword:
            params["keywordSearch"] = keyword
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        response = await self._get(
            "/cves/2.0", params={**params, "resultsPerPage": 1, "startIndex": 0}
        )
        response.raise_for_status()
        return int(response.json().get("totalResults", 0))

    def _parse_cve(self, vuln_data: dict[str, Any]) -> CVEEntry:
        """Parse a single CVE vulnerability record.

        Args:
            vuln_data: Raw vulnerability data from NVD API.

        Returns:
            Parsed CVEEntry instance.
        """
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        description = ""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        severity = CVESeverity.UNKNOWN

        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")

                if cvss_score >= 9.0:
                    severity = CVESeverity.CRITICAL
                elif cvss_score >= 7.0:
                    severity = CVESeverity.HIGH
                elif cvss_score >= 4.0:
                    severity = CVESeverity.MEDIUM
                elif cvss_score > 0.0:
                    severity = CVESeverity.LOW
                else:
                    severity = CVESeverity.NONE
                break

        published_date = None
        pub_str = cve.get("published")
        if pub_str:
            try:
                published_date = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        last_modified = None
        mod_str = cve.get("lastModified")
        if mod_str:
            try:
                last_modified = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        references: list[str] = []
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        affected_products: list[CVEAffectedProduct] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_str = match.get("criteria", "")
                    parts = cpe_str.split(":") if cpe_str else []
                    affected_products.append(
                        CVEAffectedProduct(
                            vendor=parts[3] if len(parts) > 3 else "",
                            product=parts[4] if len(parts) > 4 else "",
                            version=parts[5] if len(parts) > 5 else "",
                            cpe=cpe_str,
                        )
                    )

        weaknesses: list[str] = []
        for problem in cve.get("weaknesses", []):
            for desc in problem.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))

        return CVEEntry(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published_date=published_date,
            last_modified=last_modified,
            references=references,
            affected_products=affected_products,
            weaknesses=weaknesses,
            source="NVD",
            raw_data=vuln_data,
        )

    def _parse_search_result(self, data: dict[str, Any]) -> CVESearchResult:
        """Parse a CVE search API response.

        Args:
            data: Raw search response JSON.

        Returns:
            Parsed CVESearchResult instance.
        """
        entries: list[CVEEntry] = []
        for vuln in data.get("vulnerabilities", []):
            entries.append(self._parse_cve(vuln))

        return CVESearchResult(
            total_results=data.get("totalResults", 0),
            entries=entries,
        )
