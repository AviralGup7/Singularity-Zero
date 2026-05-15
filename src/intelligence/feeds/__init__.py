"""Threat intelligence feed connectors for the Cyber Security Test Pipeline.

Provides integrations with external threat intelligence sources including
VirusTotal, Shodan, AlienVault OTX, CVE databases, and MITRE ATT&CK
framework mapping for enriched security analysis.

Usage:
    from src.intelligence.feeds import VirusTotalClient, ShodanClient, OTXClient
    from src.intelligence.feeds import CVESyncClient, MitreAttackMapper

    vt = VirusTotalClient(api_key="...")
    report = await vt.get_ip_report("1.1.1.1")
"""

__version__ = "1.0.0"

__all__ = [
    "BaseFeedConnector",
    "CVEEntry",
    "CVESyncClient",
    "MitreAttackMapper",
    "MitreTechnique",
    "OTXClient",
    "OTXPulse",
    "ShodanClient",
    "ShodanHost",
    "VirusTotalClient",
    "VirusTotalReport",
    "VirusTotalVerdict",
    "__version__",
]


def __getattr__(name: str) -> object:
    if name == "BaseFeedConnector":
        from src.intelligence.feeds.base import BaseFeedConnector

        return BaseFeedConnector
    if name == "VirusTotalClient":
        from src.intelligence.feeds.virustotal import VirusTotalClient

        return VirusTotalClient
    if name == "VirusTotalReport":
        from src.intelligence.feeds.virustotal import VirusTotalReport

        return VirusTotalReport
    if name == "VirusTotalVerdict":
        from src.intelligence.feeds.virustotal import VirusTotalVerdict

        return VirusTotalVerdict
    if name == "ShodanClient":
        from src.intelligence.feeds.shodan import ShodanClient

        return ShodanClient
    if name == "ShodanHost":
        from src.intelligence.feeds.shodan import ShodanHost

        return ShodanHost
    if name == "OTXClient":
        from src.intelligence.feeds.otx import OTXClient

        return OTXClient
    if name == "OTXPulse":
        from src.intelligence.feeds.otx import OTXPulse

        return OTXPulse
    if name == "CVESyncClient":
        from src.intelligence.feeds.cve import CVESyncClient

        return CVESyncClient
    if name == "CVEEntry":
        from src.intelligence.feeds.cve import CVEEntry

        return CVEEntry
    if name == "MitreAttackMapper":
        from src.intelligence.feeds.mitre import MitreAttackMapper

        return MitreAttackMapper
    if name == "MitreTechnique":
        from src.intelligence.feeds.mitre import MitreTechnique

        return MitreTechnique
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
