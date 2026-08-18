"""Coverage for previously untested threat-intel enricher helpers."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.intelligence.risk.threat_intel_enricher import (
    ThreatIntelEnricher,
    ThreatIntelSummary,
    get_default_threat_intel_enricher,
    reset_default_threat_intel_enricher,
)


@dataclass
class _Record:
    epss_score: float = 0.0
    percentile: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {"epss_score": self.epss_score, "percentile": self.percentile}


class _Lookup:
    def __init__(self, mapping: dict[str, _Record | None]) -> None:
        self.mapping = mapping

    def lookup(self, cve: str) -> _Record | None:
        return self.mapping.get(cve)


@pytest.mark.unit
def test_summary_has_signal_and_to_dict() -> None:
    empty = ThreatIntelSummary()
    assert empty.has_signal is False
    payload = empty.to_dict()
    assert payload["has_signal"] is False
    assert payload["exploit_maturity"] == "X"

    hot = ThreatIntelSummary(cisa_kev=True, epss_score=0.8)
    assert hot.has_signal is True
    assert hot.to_dict()["epss_score"] == 0.8


@pytest.mark.unit
@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        ({}, []),
        ({"cve_correlations": ["cve-2024-1111", "CVE-2024-1111", "not-a-cve"]}, ["CVE-2024-1111"]),
        ({"threat_intel": {"cves": ["CVE-2023-1", ""]}}, ["CVE-2023-1"]),
    ],
)
def test_extract_cves(finding: dict[str, object], expected: list[str]) -> None:
    assert ThreatIntelEnricher._extract_cves(finding) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        ({}, ""),
        ({"url": "https://API.Example.com:8443/x"}, "api.example.com"),
        ({"target": "https://evil.test/path"}, "evil.test"),
        ({"target_endpoint": "not-a-url"}, ""),
    ],
)
def test_extract_host(finding: dict[str, object], expected: str) -> None:
    assert ThreatIntelEnricher._extract_host(finding) == expected


@pytest.mark.unit
def test_enrich_finding_does_not_mutate_and_merges_existing() -> None:
    original = {
        "id": "f1",
        "cve_correlations": ["CVE-2024-9999"],
        "threat_intel": {"note": "keep"},
    }
    enricher = ThreatIntelEnricher(
        epss_client=_Lookup({"CVE-2024-9999": _Record(epss_score=0.6, percentile=0.9)}),
        kev_client=_Lookup({}),
        correlator=None,
        network_enabled=True,
    )
    out = enricher.enrich_finding(original)
    assert original.get("threat_intel") == {"note": "keep"}
    assert out is not original
    assert out["threat_intel"]["note"] == "keep"
    assert out["threat_intel"]["epss_score"] == 0.6
    assert out["threat_intel"]["exploit_maturity"] == "A"
    assert "epss" in out["threat_intel"]["sources"]


@pytest.mark.unit
def test_summarise_kev_forces_maturity_a() -> None:
    enricher = ThreatIntelEnricher(
        epss_client=_Lookup({"CVE-2024-1": _Record(epss_score=0.05, percentile=0.2)}),
        kev_client=_Lookup({"CVE-2024-1": _Record()}),
        correlator=None,
        network_enabled=True,
    )
    summary = enricher.summarise({"cve_correlations": ["CVE-2024-1"]})
    assert summary.cisa_kev is True
    assert summary.exploit_maturity == "A"
    assert "cisa_kev" in summary.sources
    assert "epss" in summary.sources


@pytest.mark.unit
def test_summarise_offline_skips_network_lookups() -> None:
    enricher = ThreatIntelEnricher(
        epss_client=_Lookup({"CVE-2024-1": _Record(epss_score=0.9)}),
        kev_client=_Lookup({"CVE-2024-1": _Record()}),
        correlator=None,
        network_enabled=False,
    )
    summary = enricher.summarise({"cve_correlations": ["CVE-2024-1"]})
    assert summary.epss_score == 0.0
    assert summary.cisa_kev is False
    assert summary.sources == []


@pytest.mark.unit
def test_summarise_partial_epss_maturity_and_lookup_miss() -> None:
    enricher = ThreatIntelEnricher(
        epss_client=_Lookup(
            {
                "CVE-2024-LOW": _Record(epss_score=0.05, percentile=0.1),
                "CVE-2024-MISS": None,
            }
        ),
        kev_client=_Lookup({}),
        correlator=None,
        network_enabled=True,
    )
    summary = enricher.summarise({"cve_correlations": ["CVE-2024-LOW", "CVE-2024-MISS"]})
    assert summary.exploit_maturity == "U"
    assert summary.epss_score == 0.05
    assert len(summary.epss_records) == 1


@pytest.mark.unit
def test_enrich_findings_and_default_singleton() -> None:
    reset_default_threat_intel_enricher()
    first = get_default_threat_intel_enricher()
    assert get_default_threat_intel_enricher() is first
    reset_default_threat_intel_enricher()
    assert get_default_threat_intel_enricher() is not first

    enricher = ThreatIntelEnricher(network_enabled=False, correlator=None)
    outs = enricher.enrich_findings([{"id": "a"}, {"id": "b"}])
    assert [item["id"] for item in outs] == ["a", "b"]
    assert all("threat_intel" in item for item in outs)
