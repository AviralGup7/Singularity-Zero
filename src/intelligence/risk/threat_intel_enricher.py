"""Normalized threat intelligence cache.

Wraps the in-process threat intel clients (MISP, OTX, VirusTotal,
EPSS, CISA KEV) and exposes a single ``ThreatIntelEnricher`` with
a deterministic shape so callers don't have to know which feed a
piece of data came from. Findings are tagged with::

    threat_intel = {
        "cisa_kev": bool,
        "cisa_kev_records": [...],
        "epss_score": float,
        "epss_percentile": float,
        "epss_records": [...],
        "ioc_correlation": {...} | None,
        "exploit_maturity": "X"|"U"|"P"|"A",
        "sources": ["epss", "cisa_kev", "misp", "otx", "virustotal"],
        "updated_at": ts,
    }

The enricher never *mutates* a finding; it returns a new dict so
the original telemetry records stay pristine.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelSummary:
    """The aggregated threat intel view for a single finding."""

    cisa_kev: bool = False
    cisa_kev_records: list[dict[str, Any]] = field(default_factory=list)
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    epss_records: list[dict[str, Any]] = field(default_factory=list)
    ioc_correlation: dict[str, Any] | None = None
    ioc_malicious: bool = False
    exploit_maturity: str = "X"
    sources: list[str] = field(default_factory=list)
    updated_at: float = 0.0

    @property
    def has_signal(self) -> bool:
        return any(
            [
                self.cisa_kev,
                self.epss_score > 0.0,
                bool(self.ioc_correlation),
                self.ioc_malicious,
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cisa_kev": self.cisa_kev,
            "cisa_kev_records": list(self.cisa_kev_records),
            "epss_score": round(self.epss_score, 4),
            "epss_percentile": round(self.epss_percentile, 4),
            "epss_records": list(self.epss_records),
            "ioc_correlation": self.ioc_correlation,
            "ioc_malicious": self.ioc_malicious,
            "exploit_maturity": self.exploit_maturity,
            "sources": list(self.sources),
            "updated_at": self.updated_at,
            "has_signal": self.has_signal,
        }


class ThreatIntelEnricher:
    """Combine all threat intel sources behind a single API."""

    def __init__(
        self,
        *,
        epss_client: Any | None = None,
        kev_client: Any | None = None,
        correlator: Any | None = None,
        network_enabled: bool | None = None,
    ) -> None:
        self._epss = epss_client
        self._kev = kev_client
        self._correlator = correlator
        self._lock = threading.RLock()
        if network_enabled is None:
            network_enabled = os.environ.get("PIPELINE_OFFLINE", "").strip().lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }
        self._network_enabled = network_enabled

    # -- clients (lazy loaded) ----------------------------------------

    def _get_epss(self) -> Any:
        if self._epss is None:
            from src.intelligence.risk.epss import get_default_epss_client as _get_epss_client

            self._epss = _get_epss_client()
        return self._epss

    def _get_kev(self) -> Any:
        if self._kev is None:
            from src.intelligence.risk.cisa_kev import (
                get_default_cisa_kev_client as _get_kev_client,
            )

            self._kev = _get_kev_client()
        return self._kev

    def _get_correlator(self) -> Any | None:
        if self._correlator is None:
            try:
                from src.intelligence.threat_intel import ThreatIntelCorrelator

                self._correlator = ThreatIntelCorrelator()
            except Exception:  # noqa: BLE001
                self._correlator = None
        return self._correlator

    # -- public --------------------------------------------------------

    def summarise(self, finding: dict[str, Any]) -> ThreatIntelSummary:
        """Build a ``ThreatIntelSummary`` without mutating the finding."""
        summary = ThreatIntelSummary(updated_at=time.time())

        # EPSS
        if self._network_enabled:
            try:
                cves = self._extract_cves(finding)
            except Exception:  # noqa: BLE001
                cves = []
            for cve in cves:
                try:
                    record = self._get_epss().lookup(cve)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("ThreatIntelEnricher: EPSS lookup failed for %s: %s", cve, exc)
                    record = None
                if record is None:
                    continue
                summary.epss_records.append(record.to_dict())
                summary.epss_score = max(summary.epss_score, record.epss_score)
                summary.epss_percentile = max(summary.epss_percentile, record.percentile)
                if record.epss_score >= 0.5:
                    summary.exploit_maturity = "A"
                elif record.epss_score >= 0.1 and summary.exploit_maturity not in {"A"}:
                    summary.exploit_maturity = "P"
                elif record.epss_score > 0 and summary.exploit_maturity not in {"A", "P"}:
                    summary.exploit_maturity = "U"
            if summary.epss_records:
                summary.sources.append("epss")

            # CISA KEV
            for cve in cves:
                try:
                    record = self._get_kev().lookup(cve)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("ThreatIntelEnricher: KEV lookup failed for %s: %s", cve, exc)
                    record = None
                if record is None:
                    continue
                summary.cisa_kev = True
                summary.cisa_kev_records.append(record.to_dict())
                summary.exploit_maturity = "A"
            if summary.cisa_kev_records:
                summary.sources.append("cisa_kev")

        # IOC correlation (synchronous, no network needed)
        host = self._extract_host(finding)
        if host:
            try:
                correlator = self._get_correlator()
                if correlator is not None and correlator.enable_threat_intel:
                    ioc = correlator.match_ioc(host)
                    if ioc:
                        summary.ioc_correlation = ioc
                        summary.ioc_malicious = bool(ioc.get("malicious"))
                        summary.sources.append("ioc_correlator")
            except Exception as exc:  # noqa: BLE001
                logger.debug("ThreatIntelEnricher: IOC correlator failed: %s", exc)

        return summary

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of the finding with ``threat_intel`` attached."""
        summary = self.summarise(finding)
        finding = dict(finding)
        existing = dict(finding.get("threat_intel") or {})
        existing.update(summary.to_dict())
        finding["threat_intel"] = existing
        return finding

    def enrich_findings(self, findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.enrich_finding(f) for f in findings]

    # -- helpers -------------------------------------------------------

    @staticmethod
    def _extract_cves(finding: dict[str, Any]) -> list[str]:
        cves: list[str] = []
        for source in (
            finding.get("cve_correlations"),
            (finding.get("threat_intel") or {}).get("cves"),
        ):
            if not source:
                continue
            for item in source:
                if not item:
                    continue
                text = str(item).strip().upper()
                if text.startswith("CVE-") and text not in cves:
                    cves.append(text)
        if not cves and finding.get("category"):
            try:
                from src.intelligence.threat_intel import ThreatIntelCorrelator

                cves.extend(ThreatIntelCorrelator().correlate_cve(str(finding.get("category", ""))))
            except Exception:  # noqa: BLE001
                pass
        return [c for c in cves if c]

    @staticmethod
    def _extract_host(finding: dict[str, Any]) -> str:
        url = finding.get("url") or finding.get("target") or finding.get("target_endpoint")
        if not url:
            return ""
        from urllib.parse import urlparse

        host = urlparse(str(url)).netloc
        return host.split(":")[0].lower() if host else ""


# ---------------------------------------------------------------------------
# Module-level default enricher
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_enricher: ThreatIntelEnricher | None = None


def get_default_threat_intel_enricher() -> ThreatIntelEnricher:
    global _default_enricher
    with _default_lock:
        if _default_enricher is None:
            _default_enricher = ThreatIntelEnricher()
        return _default_enricher


def reset_default_threat_intel_enricher() -> None:
    global _default_enricher
    with _default_lock:
        _default_enricher = None


__all__ = [
    "ThreatIntelEnricher",
    "ThreatIntelSummary",
    "get_default_threat_intel_enricher",
    "reset_default_threat_intel_enricher",
]
