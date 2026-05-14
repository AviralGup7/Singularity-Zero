"""MITRE ATT&CK framework mapping and technique intelligence.

Provides access to MITRE ATT&CK technique data, tactic classification,
mitigation recommendations, and group/software attribution for threat
actor behavior analysis and detection engineering.

Usage:
    from src.intelligence.feeds.mitre import MitreAttackMapper, MitreConfig

    config = MitreConfig()
    async with MitreAttackMapper(config) as mapper:
        technique = await mapper.get_technique("T1059")
        mitigations = await mapper.get_mitigations_for_technique("T1059")
"""

import logging
from typing import Any

from pydantic import BaseModel, Field

from src.intelligence.feeds.base import BaseFeedConnector, FeedConfig

logger = logging.getLogger(__name__)

MITRE_BASE_URL = "https://attack.mitre.org"
MITRE_API_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack"


class MitreConfig(FeedConfig):
    """Configuration for the MITRE ATT&CK data connector.

    Attributes:
        api_key: Not used for MITRE (public data). Defaults to empty.
        base_url: MITRE ATT&CK data source URL.
        timeout_seconds: Request timeout.
        max_retries: Maximum retry attempts.
    """

    api_key: str = Field(default="")
    base_url: str = Field(default=MITRE_API_URL)
    timeout_seconds: float = Field(default=60.0, gt=0)
    max_retries: int = Field(default=3, ge=0)


class MitreTactic(BaseModel):
    """A MITRE ATT&CK tactic (the "why" of a technique).

    Attributes:
        id: Tactic identifier (e.g., TA0002).
        name: Tactic name (e.g., Execution).
        description: Tactic description.
        url: MITRE ATT&CK web page URL.
    """

    id: str
    name: str
    description: str = Field(default="")
    url: str = Field(default="")


class MitreMitigation(BaseModel):
    """A mitigation recommendation for an ATT&CK technique.

    Attributes:
        id: Mitigation identifier (e.g., M1042).
        name: Mitigation name.
        description: Mitigation description.
        url: MITRE ATT&CK web page URL.
    """

    id: str
    name: str
    description: str = Field(default="")
    url: str = Field(default="")


class MitreDataSource(BaseModel):
    """A data source relevant to detecting a technique.

    Attributes:
        name: Data source name.
        data_components: List of specific data components.
    """

    name: str
    data_components: list[str] = Field(default_factory=list)


class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique entry.

    Attributes:
        id: Technique identifier (e.g., T1059).
        name: Technique name (e.g., Command and Scripting Interpreter).
        description: Technique description.
        tactics: List of associated tactics.
        platforms: Target platforms (Windows, Linux, macOS, etc.).
        permissions_required: Required privilege level.
        detection_sources: Data sources useful for detection.
        mitigations: List of applicable mitigations.
        subtechniques: List of sub-technique IDs.
        url: MITRE ATT&CK web page URL.
        raw_data: Raw STIX object data.
    """

    id: str
    name: str
    description: str = Field(default="")
    tactics: list[MitreTactic] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    permissions_required: list[str] = Field(default_factory=list)
    detection_sources: list[MitreDataSource] = Field(default_factory=list)
    mitigations: list[MitreMitigation] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
    url: str = Field(default="")
    raw_data: dict[str, Any] = Field(default_factory=dict)


class MitreGroup(BaseModel):
    """A MITRE ATT&CK threat actor group.

    Attributes:
        id: Group identifier (e.g., G0096).
        name: Group name.
        description: Group description.
        aliases: Known aliases for the group.
        associated_techniques: List of technique IDs used by this group.
        url: MITRE ATT&CK web page URL.
        raw_data: Raw STIX object data.
    """

    id: str
    name: str
    description: str = Field(default="")
    aliases: list[str] = Field(default_factory=list)
    associated_techniques: list[str] = Field(default_factory=list)
    url: str = Field(default="")
    raw_data: dict[str, Any] = Field(default_factory=dict)


class MitreSoftware(BaseModel):
    """A MITRE ATT&CK malware or tool entry.

    Attributes:
        id: Software identifier (e.g., S0029).
        name: Software name.
        description: Software description.
        types: Software types (malware, tool, RAT, etc.).
        platforms: Target platforms.
        associated_techniques: Techniques this software implements.
        url: MITRE ATT&CK web page URL.
        raw_data: Raw STIX object data.
    """

    id: str
    name: str
    description: str = Field(default="")
    types: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    associated_techniques: list[str] = Field(default_factory=list)
    url: str = Field(default="")
    raw_data: dict[str, Any] = Field(default_factory=dict)


class MitreAttackMapper(BaseFeedConnector):
    """MITRE ATT&CK framework client for threat behavior mapping.

    Loads ATT&CK data from the MITRE CTI repository and provides
    technique lookups, tactic enumeration, mitigation mapping,
    and threat actor/software correlation.

    Attributes:
        config: MITRE configuration.
        _enterprise_data: Cached enterprise ATT&CK STIX data.
    """

    def __init__(self, config: MitreConfig) -> None:
        full_config = FeedConfig(
            api_key=config.api_key or "anonymous",
            base_url="https://raw.githubusercontent.com",
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            verify_ssl=config.verify_ssl,
            user_agent=config.user_agent,
            extra_headers=config.extra_headers,
        )
        super().__init__(full_config)
        self._mitre_config = config
        self._enterprise_data: dict[str, list[dict[str, Any]]] | None = None

    @property
    def client_name(self) -> str:
        return "MITRE ATT&CK"

    async def _load_enterprise_data(self) -> dict[str, list[dict[str, Any]]]:
        """Load and cache the enterprise ATT&CK STIX bundle.

        Returns:
            Dict mapping STIX types to lists of STIX objects.
        """
        if self._enterprise_data is not None:
            return self._enterprise_data

        response = await self._get("/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        response.raise_for_status()
        bundle = response.json()

        categorized: dict[str, list[dict[str, Any]]] = {}
        for obj in bundle.get("objects", []):
            stix_type = obj.get("type", "unknown")
            if stix_type not in categorized:
                categorized[stix_type] = []
            categorized[stix_type].append(obj)

        self._enterprise_data = categorized
        return categorized

    async def get_technique(self, technique_id: str) -> MitreTechnique | None:
        """Retrieve a specific ATT&CK technique by ID.

        Args:
            technique_id: Technique ID (e.g., "T1059", "T1059.001").

        Returns:
            MitreTechnique if found, None otherwise.
        """
        data = await self._load_enterprise_data()
        attack_patterns = data.get("attack-pattern", [])

        for obj in attack_patterns:
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if (
                    ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id") == technique_id
                ):
                    return self._parse_technique(obj, attack_patterns)

        return None

    async def get_techniques_by_tactic(self, tactic_id: str) -> list[MitreTechnique]:
        """Retrieve all techniques associated with a specific tactic.

        Args:
            tactic_id: Tactic ID (e.g., "TA0002").

        Returns:
            List of MitreTechnique for the given tactic.
        """
        data = await self._load_enterprise_data()
        attack_patterns = data.get("attack-pattern", [])
        techniques: list[MitreTechnique] = []

        for obj in attack_patterns:
            kill_chains = obj.get("kill_chain_phases", [])
            for phase in kill_chains:
                if phase.get("phase_name") == tactic_id.lower().replace("ta", ""):
                    technique = self._parse_technique(obj, attack_patterns)
                    techniques.append(technique)
                    break

        return techniques

    async def get_mitigations_for_technique(self, technique_id: str) -> list[MitreMitigation]:
        """Retrieve mitigations applicable to a specific technique.

        Args:
            technique_id: Technique ID.

        Returns:
            List of applicable MitreMitigation records.
        """
        data = await self._load_enterprise_data()
        attack_patterns = data.get("attack-pattern", [])
        mitigations_data = data.get("course-of-action", [])

        technique_obj = None
        for obj in attack_patterns:
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if (
                    ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id") == technique_id
                ):
                    technique_obj = obj
                    break
            if technique_obj:
                break

        if not technique_obj:
            return []

        technique_stix_id = technique_obj.get("id", "")
        relationships = data.get("relationship", [])
        mitigation_ids: set[str] = set()

        for rel in relationships:
            if (
                rel.get("relationship_type") == "mitigates"
                and rel.get("target_ref") == technique_stix_id
            ):
                mitigation_ids.add(rel.get("source_ref", ""))

        mitigations: list[MitreMitigation] = []
        for mit_obj in mitigations_data:
            if mit_obj.get("id") in mitigation_ids:
                mitigations.append(self._parse_mitigation(mit_obj))

        return mitigations

    async def get_group(self, group_id: str) -> MitreGroup | None:
        """Retrieve a threat actor group by ID.

        Args:
            group_id: Group ID (e.g., "G0096").

        Returns:
            MitreGroup if found, None otherwise.
        """
        data = await self._load_enterprise_data()
        intrusion_sets = data.get("intrusion-set", [])

        for obj in intrusion_sets:
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == group_id:
                    return self._parse_group(obj, data)

        return None

    async def get_software(self, software_id: str) -> MitreSoftware | None:
        """Retrieve malware/tool software by ID.

        Args:
            software_id: Software ID (e.g., "S0029").

        Returns:
            MitreSoftware if found, None otherwise.
        """
        data = await self._load_enterprise_data()
        malware_objs = data.get("malware", [])
        tool_objs = data.get("tool", [])

        for obj in malware_objs + tool_objs:
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if (
                    ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id") == software_id
                ):
                    return self._parse_software(obj, data)

        return None

    async def get_all_techniques(self) -> list[MitreTechnique]:
        """Retrieve all enterprise ATT&CK techniques.

        Returns:
            List of all MitreTechnique entries.
        """
        data = await self._load_enterprise_data()
        attack_patterns = data.get("attack-pattern", [])
        techniques: list[MitreTechnique] = []

        for obj in attack_patterns:
            technique = self._parse_technique(obj, attack_patterns)
            techniques.append(technique)

        return techniques

    async def get_all_tactics(self) -> list[MitreTactic]:
        """Retrieve all enterprise ATT&CK tactics.

        Returns:
            List of all MitreTactic entries.
        """
        data = await self._load_enterprise_data()
        x_mitre_tactics = data.get("x-mitre-tactic", [])
        tactics: list[MitreTactic] = []

        for obj in x_mitre_tactics:
            external_refs = obj.get("external_references", [])
            tactic_id = ""
            url = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break

            if tactic_id:
                tactics.append(
                    MitreTactic(
                        id=tactic_id,
                        name=obj.get("name", ""),
                        description=obj.get("description", ""),
                        url=url,
                    )
                )

        return tactics

    async def get_all_groups(self) -> list[MitreGroup]:
        """Retrieve all enterprise ATT&CK threat actor groups.

        Returns:
            List of all MitreGroup entries.
        """
        data = await self._load_enterprise_data()
        intrusion_sets = data.get("intrusion-set", [])
        groups: list[MitreGroup] = []

        for obj in intrusion_sets:
            group = self._parse_group(obj, data)
            groups.append(group)

        return groups

    def _parse_technique(
        self,
        obj: dict[str, Any],
        all_patterns: list[dict[str, Any]],
    ) -> MitreTechnique:
        """Parse a STIX attack-pattern object into a MitreTechnique.

        Args:
            obj: Raw STIX attack-pattern object.
            all_patterns: All attack-pattern objects for sub-technique lookup.

        Returns:
            Parsed MitreTechnique instance.
        """
        external_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        kill_chains = obj.get("kill_chain_phases", [])
        tactics: list[MitreTactic] = []
        for phase in kill_chains:
            tactics.append(
                MitreTactic(
                    id=phase.get("phase_name", "").upper(),
                    name=phase.get("phase_name", ""),
                )
            )

        x_mitre_platforms = obj.get("x_mitre_platforms", [])
        x_mitre_permissions = obj.get("x_mitre_permissions_required", [])
        obj.get("x_mitre_detection", "")

        subtechniques: list[str] = []
        technique_stix_id = obj.get("id", "")
        for other in all_patterns:
            if other.get("id", "").startswith(technique_stix_id + "."):
                for eref in other.get("external_references", []):
                    if eref.get("source_name") == "mitre-attack":
                        subtechniques.append(eref.get("external_id", ""))
                        break

        return MitreTechnique(
            id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            tactics=tactics,
            platforms=x_mitre_platforms,
            permissions_required=x_mitre_permissions,
            detection_sources=[],
            mitigations=[],
            subtechniques=subtechniques,
            url=url,
            raw_data=obj,
        )

    def _parse_mitigation(self, obj: dict[str, Any]) -> MitreMitigation:
        """Parse a STIX course-of-action object.

        Args:
            obj: Raw STIX course-of-action object.

        Returns:
            Parsed MitreMitigation instance.
        """
        external_refs = obj.get("external_references", [])
        mit_id = ""
        url = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mit_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        return MitreMitigation(
            id=mit_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            url=url,
        )

    def _parse_group(
        self,
        obj: dict[str, Any],
        data: dict[str, list[dict[str, Any]]],
    ) -> MitreGroup:
        """Parse a STIX intrusion-set object into a MitreGroup.

        Args:
            obj: Raw STIX intrusion-set object.
            data: Full enterprise ATT&CK data.

        Returns:
            Parsed MitreGroup instance.
        """
        external_refs = obj.get("external_references", [])
        group_id = ""
        url = ""
        aliases = obj.get("aliases", [])

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        group_stix_id = obj.get("id", "")
        relationships = data.get("relationship", [])
        technique_ids: list[str] = []

        for rel in relationships:
            if rel.get("relationship_type") == "uses" and rel.get("source_ref") == group_stix_id:
                target_ref = rel.get("target_ref", "")
                if target_ref.startswith("attack-pattern--"):
                    for pat in data.get("attack-pattern", []):
                        if pat.get("id") == target_ref:
                            for eref in pat.get("external_references", []):
                                if eref.get("source_name") == "mitre-attack":
                                    technique_ids.append(eref.get("external_id", ""))
                                    break

        return MitreGroup(
            id=group_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            aliases=aliases,
            associated_techniques=technique_ids,
            url=url,
            raw_data=obj,
        )

    def _parse_software(
        self,
        obj: dict[str, Any],
        data: dict[str, list[dict[str, Any]]],
    ) -> MitreSoftware:
        """Parse a STIX malware/tool object into a MitreSoftware.

        Args:
            obj: Raw STIX malware or tool object.
            data: Full enterprise ATT&CK data.

        Returns:
            Parsed MitreSoftware instance.
        """
        external_refs = obj.get("external_references", [])
        software_id = ""
        url = ""

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                software_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        software_type = obj.get("type", "")
        types = [software_type]
        if software_type == "malware":
            malware_types = obj.get("malware_types", [])
            types.extend(malware_types)

        platforms = obj.get("x_mitre_platforms", [])

        software_stix_id = obj.get("id", "")
        relationships = data.get("relationship", [])
        technique_ids: list[str] = []

        for rel in relationships:
            if rel.get("relationship_type") == "uses" and rel.get("source_ref") == software_stix_id:
                target_ref = rel.get("target_ref", "")
                if target_ref.startswith("attack-pattern--"):
                    for pat in data.get("attack-pattern", []):
                        if pat.get("id") == target_ref:
                            for eref in pat.get("external_references", []):
                                if eref.get("source_name") == "mitre-attack":
                                    technique_ids.append(eref.get("external_id", ""))
                                    break

        return MitreSoftware(
            id=software_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            types=types,
            platforms=platforms,
            associated_techniques=technique_ids,
            url=url,
            raw_data=obj,
        )
