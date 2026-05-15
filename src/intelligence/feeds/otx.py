"""AlienVault Open Threat Exchange (OTX) integration.

Provides access to OTX threat intelligence pulses, indicators of compromise
(IOCs), threat actor attribution, and malware tracking through the
AlienVault OTX API.

Environment Variables:
    OTX_API_KEY: AlienVault OTX API key (required).

Usage:
    from src.intelligence.feeds.otx import OTXClient, OTXConfig

    config = OTXConfig(api_key="...")
    async with OTXClient(config) as client:
        pulses = await client.get_user_pulses("alienvault")
        indicators = await client.get_indicator_details("IPv4", "1.1.1.1")
"""

import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.intelligence.feeds.base import BaseFeedConnector, FeedConfig

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


class OTXConfig(FeedConfig):
    """Configuration for the AlienVault OTX API connector.

    Attributes:
        api_key: OTX API key.
        base_url: OTX API base URL.
        timeout_seconds: Request timeout.
        max_retries: Maximum retry attempts.
    """

    api_key: str = Field(..., min_length=1)
    base_url: str = Field(default=OTX_BASE_URL)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)


class OTXIndicator(BaseModel):
    """A single indicator of compromise from an OTX pulse.

    Attributes:
        type: Indicator type (IPv4, IPv6, domain, hostname, URL, etc.).
        value: The indicator value itself.
        title: Human-readable title or description.
        description: Detailed description of the indicator.
        created: When the indicator was added to the pulse.
    """

    type: str
    value: str
    title: str = Field(default="")
    description: str = Field(default="")
    created: datetime | None = Field(default=None)


class OTXPulse(BaseModel):
    """An OTX threat intelligence pulse.

    Pulses are collections of IOCs, analysis, and attribution curated
    by OTX contributors.

    Attributes:
        id: Pulse identifier.
        name: Pulse name/title.
        description: Pulse description.
        author_name: Username of the pulse author.
        created: Pulse creation timestamp.
        modified: Last modification timestamp.
        tags: Pulse tags.
        indicators: List of IOCs in the pulse.
        adversary: Attributed threat actor or group.
        malware_families: List of associated malware families.
        industries: Targeted industry sectors.
        public: Whether the pulse is publicly visible.
        subscriber_count: Number of OTX users subscribed to this pulse.
        raw_data: Raw API response data.
    """

    id: str
    name: str
    description: str = Field(default="")
    author_name: str = Field(default="")
    created: datetime | None = Field(default=None)
    modified: datetime | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    indicators: list[OTXIndicator] = Field(default_factory=list)
    adversary: str = Field(default="")
    malware_families: list[str] = Field(default_factory=list)
    industries: list[str] = Field(default_factory=list)
    public: bool = Field(default=True)
    subscriber_count: int = Field(default=0, ge=0)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class OTXIndicatorDetail(BaseModel):
    """Detailed intelligence for a specific indicator.

    Attributes:
        indicator: The indicator value.
        indicator_type: Type of indicator.
        pulses: List of pulses containing this indicator.
        sections: Intelligence sections (general, malware, url_list, etc.).
        raw_data: Raw API response data.
    """

    indicator: str
    indicator_type: str
    pulses: list[OTXPulse] = Field(default_factory=list)
    sections: dict[str, Any] = Field(default_factory=dict)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class OTXClient(BaseFeedConnector):
    """AlienVault OTX API client for threat intelligence.

    Provides pulse browsing, indicator lookups, subscriber management,
    and threat correlation through the OTX platform.

    Attributes:
        config: OTX configuration.
    """

    def __init__(self, config: OTXConfig) -> None:
        headers = {"X-OTX-API-KEY": config.api_key}
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
        self._otx_config = config

    @property
    def client_name(self) -> str:
        return "AlienVault OTX"

    async def get_indicator_details(
        self,
        indicator_type: str,
        indicator_value: str,
    ) -> OTXIndicatorDetail:
        """Retrieve detailed intelligence for a specific indicator.

        Args:
            indicator_type: Type (IPv4, IPv6, domain, hostname, URL, MD5, SHA1, SHA256).
            indicator_value: The indicator value to look up.

        Returns:
            OTXIndicatorDetail with pulse membership and sections.
        """
        type_map = {
            "IPv4": "IPv4",
            "IPv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "URL": "URL",
            "MD5": "file",
            "SHA1": "file",
            "SHA256": "file",
            "CIDR": "CIDR",
        }
        api_type = type_map.get(indicator_type, indicator_type)
        response = await self._get(f"/indicators/{api_type}/{indicator_value}/general")
        if response.status_code == 404:
            return OTXIndicatorDetail(
                indicator=indicator_value,
                indicator_type=indicator_type,
                raw_data={"error": "Indicator not found"},
            )
        response.raise_for_status()
        return self._parse_indicator_detail(response.json(), indicator_value, indicator_type)

    async def get_indicator_pulses(
        self,
        indicator_type: str,
        indicator_value: str,
    ) -> list[OTXPulse]:
        """Retrieve all pulses containing a specific indicator.

        Args:
            indicator_type: Type of indicator.
            indicator_value: The indicator value.

        Returns:
            List of OTXPulse records containing the indicator.
        """
        type_map = {
            "IPv4": "IPv4",
            "IPv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "URL": "URL",
            "MD5": "file",
            "SHA1": "file",
            "SHA256": "file",
            "CIDR": "CIDR",
        }
        api_type = type_map.get(indicator_type, indicator_type)
        response = await self._get(f"/indicators/{api_type}/{indicator_value}/pulses")
        response.raise_for_status()
        return self._parse_pulses_list(response.json())

    async def get_user_pulses(
        self,
        username: str,
        page: int = 1,
        limit: int = 20,
    ) -> list[OTXPulse]:
        """Retrieve pulses published by a specific OTX user.

        Args:
            username: OTX username.
            page: Page number.
            limit: Results per page.

        Returns:
            List of OTXPulse records.
        """
        response = await self._get(
            f"/pulses/user/{username}",
            params={"page": page, "limit": limit},
        )
        response.raise_for_status()
        return self._parse_pulses_list(response.json())

    async def get_pulse_by_id(self, pulse_id: str) -> OTXPulse | None:
        """Retrieve a specific pulse by its ID.

        Args:
            pulse_id: Pulse identifier.

        Returns:
            OTXPulse if found, None otherwise.
        """
        response = await self._get(f"/pulses/{pulse_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return self._parse_pulse(response.json())

    async def get_subscribed_pulses(
        self,
        page: int = 1,
        limit: int = 20,
    ) -> list[OTXPulse]:
        """Retrieve pulses the authenticated user is subscribed to.

        Args:
            page: Page number.
            limit: Results per page.

        Returns:
            List of subscribed OTXPulse records.
        """
        response = await self._get(
            "/pulses/subscribed",
            params={"page": page, "limit": limit},
        )
        response.raise_for_status()
        return self._parse_pulses_list(response.json())

    async def search_pulses(
        self,
        query: str,
        page: int = 1,
        limit: int = 20,
    ) -> list[OTXPulse]:
        """Search OTX pulses by keyword.

        Args:
            query: Search query string.
            page: Page number.
            limit: Results per page.

        Returns:
            List of matching OTXPulse records.
        """
        response = await self._get(
            "/pulses/search",
            params={"q": query, "page": page, "limit": limit},
        )
        response.raise_for_status()
        return self._parse_pulses_list(response.json())

    async def get_indicator_section(
        self,
        indicator_type: str,
        indicator_value: str,
        section: str,
    ) -> dict[str, Any]:
        """Retrieve a specific intelligence section for an indicator.

        Args:
            indicator_type: Type of indicator.
            indicator_value: The indicator value.
            section: Section name (malware, url_list, passive_dns, n6v, etc.).

        Returns:
            Dict with section-specific intelligence data.
        """
        type_map = {
            "IPv4": "IPv4",
            "IPv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "URL": "URL",
            "MD5": "file",
            "SHA1": "file",
            "SHA256": "file",
        }
        api_type = type_map.get(indicator_type, indicator_type)
        response = await self._get(f"/indicators/{api_type}/{indicator_value}/{section}")
        response.raise_for_status()
        return response.json()  # type: ignore

    async def get_passive_dns(
        self,
        indicator_type: str,
        indicator_value: str,
    ) -> list[dict[str, Any]]:
        """Retrieve passive DNS data for an indicator.

        Args:
            indicator_type: Type of indicator.
            indicator_value: The indicator value.

        Returns:
            List of passive DNS records.
        """
        type_map = {
            "IPv4": "IPv4",
            "IPv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
        }
        api_type = type_map.get(indicator_type, indicator_type)
        response = await self._get(f"/indicators/{api_type}/{indicator_value}/passive_dns")
        response.raise_for_status()
        return list(response.json().get("passive_dns", []))

    def _parse_pulse(self, data: dict[str, Any]) -> OTXPulse:
        """Parse a single OTX pulse API response.

        Args:
            data: Raw pulse data from the OTX API.

        Returns:
            Parsed OTXPulse instance.
        """
        indicators: list[OTXIndicator] = []
        for ind in data.get("indicators", []):
            created = None
            created_str = ind.get("created")
            if created_str:
                try:
                    created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            indicators.append(
                OTXIndicator(
                    type=ind.get("type", ""),
                    value=ind.get("indicator", ""),
                    title=ind.get("title", ""),
                    description=ind.get("description", ""),
                    created=created,
                )
            )

        created = None
        modified = None
        for field_name, field_val in [
            ("created", data.get("created")),
            ("modified", data.get("modified")),
        ]:
            if field_val:
                try:
                    dt = datetime.fromisoformat(str(field_val).replace("Z", "+00:00"))
                    if field_name == "created":
                        created = dt
                    else:
                        modified = dt
                except (ValueError, TypeError):
                    pass

        return OTXPulse(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            author_name=data.get("author_name", ""),
            created=created,
            modified=modified,
            tags=data.get("tags", []),
            indicators=indicators,
            adversary=data.get("adversary", ""),
            malware_families=data.get("malware_families", []),
            industries=data.get("industries", []),
            public=data.get("public", True),
            subscriber_count=data.get("subscriber_count", 0),
            raw_data=data,
        )

    def _parse_pulses_list(self, data: dict[str, Any]) -> list[OTXPulse]:
        """Parse a list of OTX pulses from API response.

        Args:
            data: Raw list response JSON.

        Returns:
            List of parsed OTXPulse instances.
        """
        pulses: list[OTXPulse] = []
        for item in data.get("results", []):
            pulses.append(self._parse_pulse(item))
        return pulses

    def _parse_indicator_detail(
        self,
        data: dict[str, Any],
        indicator: str,
        indicator_type: str,
    ) -> OTXIndicatorDetail:
        """Parse an indicator detail API response.

        Args:
            data: Raw indicator detail JSON.
            indicator: The indicator value.
            indicator_type: The indicator type.

        Returns:
            Parsed OTXIndicatorDetail instance.
        """
        return OTXIndicatorDetail(
            indicator=indicator,
            indicator_type=indicator_type,
            pulses=[],
            sections=data,
            raw_data=data,
        )
