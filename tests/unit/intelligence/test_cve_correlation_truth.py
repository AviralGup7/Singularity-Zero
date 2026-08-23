"""Category names must not invent CVEs or drive EPSS/KEV."""

from __future__ import annotations

from src.intelligence.risk.cisa_kev import CISAKEVClient
from src.intelligence.risk.epss import EPSSClient
from src.intelligence.risk.threat_intel_enricher import ThreatIntelEnricher
from src.intelligence.threat_intel import (
    NON_PRODUCTION_CATEGORY_CVE_EXAMPLES,
    ThreatIntelCorrelator,
    example_cves_for_category,
    explicit_cves_from_finding,
)


def test_correlate_cve_does_not_use_example_table() -> None:
    correlator = ThreatIntelCorrelator()
    assert correlator.correlate_cve("sql_injection") == []
    assert correlator.correlate_cve("command_injection") == []
    assert "CVE-2021-44228" in example_cves_for_category("command_injection")
    assert "sql_injection" in NON_PRODUCTION_CATEGORY_CVE_EXAMPLES


def test_explicit_cves_only_from_finding_fields() -> None:
    finding = {
        "category": "sql_injection",
        "cve_id": "cve-2024-0001",
        "cve_correlations": ["CVE-2024-0001", "not-a-cve"],
        "threat_intel": {"cves": [{"id": "CVE-2023-1111"}]},
    }
    assert explicit_cves_from_finding(finding) == ["CVE-2024-0001", "CVE-2023-1111"]
    assert explicit_cves_from_finding({"category": "xss"}) == []


def test_enrich_findings_does_not_stamp_example_cves_or_epss(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called: list[str] = []

    def _boom(finding: dict, cve: str) -> None:
        called.append(cve)

    monkeypatch.setattr(ThreatIntelCorrelator, "_attach_epss", staticmethod(_boom))
    monkeypatch.setattr(ThreatIntelCorrelator, "_attach_cisa_kev", staticmethod(_boom))

    correlator = ThreatIntelCorrelator()
    out = correlator.enrich_findings_with_intel(
        [{"id": "f1", "category": "command_injection", "type": "command_injection"}]
    )
    assert "cve_correlations" not in out[0]
    assert called == []


def test_enrich_findings_attaches_only_explicit_cves(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen: list[str] = []

    def _record(_finding: dict, cve: str) -> None:
        seen.append(cve)

    monkeypatch.setattr(ThreatIntelCorrelator, "_attach_epss", staticmethod(_record))
    monkeypatch.setattr(ThreatIntelCorrelator, "_attach_cisa_kev", staticmethod(_record))

    correlator = ThreatIntelCorrelator()
    out = correlator.enrich_findings_with_intel(
        [{"id": "f2", "category": "xss", "cve_id": "CVE-2024-2222"}]
    )
    assert seen == ["CVE-2024-2222", "CVE-2024-2222"]
    assert out[0]["cve_id"] == "CVE-2024-2222"


def test_downstream_extractors_ignore_category_examples() -> None:
    finding = {"category": "sql_injection"}
    assert ThreatIntelEnricher._extract_cves(finding) == []
    assert EPSSClient()._extract_cves(finding) == []
    assert CISAKEVClient()._extract_cves(finding) == []
