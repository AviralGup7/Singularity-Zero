"""Shodan API integration for Internet-connected device intelligence.

Provides host lookups, service enumeration, banner grabbing, and
vulnerability correlation through the Shodan search engine for
Internet-exposed asset discovery.

Environment Variables:
    SHODAN_API_KEY: Shodan API key (required).

Usage:
    from src.intelligence.feeds.shodan import ShodanClient, ShodanConfig

    config = ShodanConfig(api_key="...")
    async with ShodanClient(config) as client:
        host = await client.get_host_info("1.1.1.1")
        print(host.open_ports)
"""

import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.intelligence.feeds.base import BaseFeedConnector, FeedConfig

logger = logging.getLogger(__name__)

SHODAN_BASE_URL = "https://api.shodan.io"


class ShodanConfig(FeedConfig):
    """Configuration for the Shodan API connector.

    Attributes:
        api_key: Shodan API key.
        base_url: Shodan API base URL.
        timeout_seconds: Request timeout.
        max_retries: Maximum retry attempts.
    """

    api_key: str = Field(..., min_length=1)
    base_url: str = Field(default=SHODAN_BASE_URL)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)


class ShodanService(BaseModel):
    """A service discovered on a Shodan-scanned host.

    Attributes:
        port: Port number the service is running on.
        protocol: Transport protocol (tcp/udp).
        product: Identified software product name.
        version: Identified software version.
        extrainfo: Additional service information.
        banner: Raw service banner or response data.
        cpe: Common Platform Enumeration identifiers.
        vulns: List of identified CVEs for this service.
        timestamp: When the service was last scanned.
    """

    port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(default="tcp")
    product: str = Field(default="")
    version: str = Field(default="")
    extrainfo: str = Field(default="")
    banner: str = Field(default="")
    cpe: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    timestamp: datetime | None = Field(default=None)


class ShodanHost(BaseModel):
    """Standardized Shodan host information.

    Attributes:
        ip: IP address of the host.
        hostnames: List of DNS hostnames resolving to this IP.
        country: Country code where the host is located.
        city: City where the host is located.
        organization: Organization that owns the IP range.
        isp: Internet Service Provider.
        asn: Autonomous System Number.
        open_ports: List of open port numbers.
        services: Detailed service information per port.
        last_update: Timestamp of the last Shodan scan.
        os: Identified operating system.
        tags: Shodan-assigned tags for the host.
        raw_data: Raw API response data.
    """

    ip: str
    hostnames: list[str] = Field(default_factory=list)
    country: str = Field(default="")
    city: str = Field(default="")
    organization: str = Field(default="")
    isp: str = Field(default="")
    asn: str = Field(default="")
    open_ports: list[int] = Field(default_factory=list)
    services: list[ShodanService] = Field(default_factory=list)
    last_update: datetime | None = Field(default=None)
    os: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ShodanSearchResult(BaseModel):
    """Result from a Shodan search query.

    Attributes:
        total: Total number of matching results.
        hosts: List of matching host records.
    """

    total: int = Field(default=0, ge=0)
    hosts: list[ShodanHost] = Field(default_factory=list)


class ShodanClient(BaseFeedConnector):
    """Shodan API client for Internet asset intelligence.

    Provides host lookups, search queries, DNS resolution, and
    vulnerability enumeration through Shodan's API.

    Attributes:
        config: Shodan configuration.
    """

    def __init__(self, config: ShodanConfig) -> None:
        extra_headers = config.extra_headers or {}
        if config.api_key:
            extra_headers["Authorization"] = f"Bearer {config.api_key}"

        full_config = FeedConfig(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            verify_ssl=config.verify_ssl,
            user_agent=config.user_agent,
            extra_headers=extra_headers,
        )
        super().__init__(full_config)
        self._shodan_config = config

    @property
    def client_name(self) -> str:
        return "Shodan"

    async def get_host_info(self, ip_address: str) -> ShodanHost:
        """Retrieve full host information for an IP address.

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            Parsed ShodanHost with service and vulnerability data.

        Raises:
            FeedError: If the request fails.
        """
        response = await self._get(
            f"/shodan/host/{ip_address}",
            params={"key": self.config.api_key},
        )
        if response.status_code == 404:
            return ShodanHost(
                ip=ip_address,
                raw_data={"error": "Host not found in Shodan"},
            )
        response.raise_for_status()
        return self._parse_host(response.json())

    async def search(
        self,
        query: str,
        page: int = 1,
        minify: bool = True,
    ) -> ShodanSearchResult:
        """Search Shodan for hosts matching a query string.

        Args:
            query: Shodan search query (e.g., "port:443 org:Example").
            page: Page number for paginated results.
            minify: Whether to return minimized response fields.

        Returns:
            ShodanSearchResult with matching hosts.
        """
        response = await self._get(
            "/shodan/host/search",
            params={
                "key": self.config.api_key,
                "query": query,
                "page": page,
                "minify": minify,
            },
        )
        response.raise_for_status()
        return self._parse_search_result(response.json())

    async def get_dns_resolve(self, hostnames: list[str]) -> dict[str, str]:
        """Resolve hostnames to IP addresses via Shodan DNS.

        Args:
            hostnames: List of hostnames to resolve.

        Returns:
            Dict mapping hostnames to IP addresses.
        """
        response = await self._get(
            "/dns/resolve",
            params={
                "hostnames": ",".join(hostnames),
            },
        )
        response.raise_for_status()
        return response.json()  # type: ignore

    async def get_dns_reverse(self, ips: list[str]) -> dict[str, list[str]]:
        """Reverse DNS lookup for IP addresses via Shodan.

        Args:
            ips: List of IP addresses to look up.

        Returns:
            Dict mapping IPs to lists of hostnames.
        """
        response = await self._get(
            "/dns/reverse",
            params={
                "key": self.config.api_key,
                "ips": ",".join(ips),
            },
        )
        response.raise_for_status()
        return response.json()  # type: ignore

    async def get_host_count(self, query: str) -> int:
        """Get the total count of results for a search query.

        Args:
            query: Shodan search query string.

        Returns:
            Total number of matching hosts.
        """
        response = await self._get(
            "/shodan/host/count",
            params={
                "key": self.config.api_key,
                "query": query,
            },
        )
        response.raise_for_status()
        return int(response.json().get("total", 0))

    async def get_api_info(self) -> dict[str, Any]:
        """Retrieve API account information.

        Returns:
            Dict with API plan, credits, and scan credits info.
        """
        response = await self._get(
            "/api-info",
            params={"key": self.config.api_key},
        )
        response.raise_for_status()
        return response.json()  # type: ignore

    async def get_host_history(self, ip_address: str) -> list[ShodanHost]:
        """Retrieve historical scan data for an IP address.

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            List of ShodanHost records from historical scans.
        """
        response = await self._get(
            f"/shodan/host/{ip_address}/history",
            params={"key": self.config.api_key},
        )
        response.raise_for_status()
        data = response.json()
        hosts: list[ShodanHost] = []
        for item in data.get("data", []):
            hosts.append(self._parse_host(item))
        return hosts

    async def get_host_tags(self, ip_address: str) -> list[str]:
        """Retrieve Shodan-assigned tags for a host.

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            List of tag strings.
        """
        response = await self._get(
            f"/shodan/host/{ip_address}",
            params={"key": self.config.api_key},
        )
        response.raise_for_status()
        return list(response.json().get("tags", []))

    def _parse_host(self, data: dict[str, Any]) -> ShodanHost:
        """Parse a Shodan host API response into a ShodanHost model.

        Args:
            data: Raw host data from the Shodan API.

        Returns:
            Parsed ShodanHost instance.
        """
        services: list[ShodanService] = []
        open_ports: list[int] = []
        vulns: list[str] = []

        for item in data.get("data", []):
            port = item.get("port", 0)
            open_ports.append(port)

            timestamp = None
            ts = item.get("timestamp")
            if ts:
                try:
                    timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError, TypeError:
                    pass

            service = ShodanService(
                port=port,
                protocol=item.get("transport", "tcp"),
                product=item.get("product", ""),
                version=item.get("version", ""),
                extrainfo=item.get("extrainfo", ""),
                banner=item.get("data", ""),
                cpe=item.get("cpe", []),
                vulns=list(item.get("vulns", {}).keys())
                if isinstance(item.get("vulns"), dict)
                else [],
                timestamp=timestamp,
            )
            services.append(service)
            vulns.extend(service.vulns)

        last_update = None
        update_str = data.get("last_update")
        if update_str:
            try:
                last_update = datetime.fromisoformat(str(update_str).replace("Z", "+00:00"))
            except ValueError, TypeError:
                pass

        return ShodanHost(
            ip=data.get("ip_str", data.get("ip", "")),
            hostnames=data.get("hostnames", []),
            country=data.get("country_name", ""),
            city=data.get("city", ""),
            organization=data.get("org", ""),
            isp=data.get("isp", ""),
            asn=data.get("asn", ""),
            open_ports=open_ports,
            services=services,
            last_update=last_update,
            os=data.get("os", ""),
            tags=data.get("tags", []),
            vulns=list(set(vulns)),
            raw_data=data,
        )

    def _parse_search_result(self, data: dict[str, Any]) -> ShodanSearchResult:
        """Parse a Shodan search API response.

        Args:
            data: Raw search response JSON.

        Returns:
            Parsed ShodanSearchResult instance.
        """
        hosts: list[ShodanHost] = []
        for item in data.get("matches", []):
            hosts.append(self._parse_host(item))

        return ShodanSearchResult(
            total=data.get("total", 0),
            hosts=hosts,
        )
