"""Threat Intelligence Feed Correlation and Vulnerability Mapping Subsystem.

Integrates with threat intel sources (MISP, VirusTotal, AlienVault OTX) and matches CVE databases.

The correlator now also enriches findings with:

* **CISA KEV** (Known Exploited Vulnerabilities) - the official
  catalogue of CVEs being actively exploited.
* **EPSS** (Exploit Prediction Scoring System) - a daily score
  estimating the probability a CVE will be exploited over the
  next 30 days.

Both feeds are opt-in (no API key needed for CISA KEV; EPSS is
public). Local simulation fallbacks remain available but are now
gated on an explicit ``test_mode`` configuration flag rather than
detecting ``pytest`` in ``sys.modules`` - the previous heuristic
risked triggering simulation on production hosts when tests were
imported but not running.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from src.core.utils import indicator_type_for, is_ip

logger = logging.getLogger(__name__)


def _is_test_mode() -> bool:
    """Return True only when the operator has explicitly opted in.

    We intentionally do *not* sniff ``sys.modules`` for ``pytest`` or
    ``unittest``. Both modules can be imported during a normal
    application boot (for example by coverage tools or by code
    that performs its own introspection), and the previous
    heuristic would silently flip the threat-intel correlator
    into simulation mode on production hosts. Operators must now
    set ``PIPELINE_THREAT_INTEL_TEST_MODE=1`` to enable the
    simulated sandbox cache.
    """
    flag = os.environ.get("PIPELINE_THREAT_INTEL_TEST_MODE", "").strip().lower()
    return flag in {"1", "true", "yes", "on"}


# Illustrative category→CVE samples for docs/tests only.
# NOT a correlation: these IDs are unrelated third-party bugs (e.g. Log4Shell
# is not "command injection"). Production enrichers must not consult this table.
NON_PRODUCTION_CATEGORY_CVE_EXAMPLES: dict[str, tuple[str, ...]] = {
    "sql_injection": ("CVE-2024-27956", "CVE-2023-46574", "CVE-2023-38646"),
    "command_injection": ("CVE-2024-21887", "CVE-2023-49103", "CVE-2021-44228"),
    "xss": ("CVE-2024-25600", "CVE-2023-30777", "CVE-2023-34992"),
    "idor": ("CVE-2024-28757", "CVE-2023-49070"),
    "ssrf": ("CVE-2024-27198", "CVE-2023-26360", "CVE-2021-26084"),
    "broken_access_control": ("CVE-2024-21626", "CVE-2023-38646"),
}


def example_cves_for_category(finding_category: str) -> list[str]:
    """Return labeled non-production example CVEs. Never used to stamp findings."""
    cat = str(finding_category or "").strip().lower()
    return list(NON_PRODUCTION_CATEGORY_CVE_EXAMPLES.get(cat, ()))


def explicit_cves_from_finding(finding: dict[str, Any]) -> list[str]:
    """Collect CVE IDs already present on a finding. Does not invent IDs from category."""
    collected: list[str] = []

    def _add(raw: object) -> None:
        if raw is None:
            return
        if isinstance(raw, dict):
            _add(raw.get("id") or raw.get("cve_id") or raw.get("cve"))
            return
        text = str(raw).strip().upper()
        if not text.startswith("CVE-") or text in collected:
            return
        collected.append(text)

    _add(finding.get("cve_id"))
    _add(finding.get("cve"))
    for source in (
        finding.get("cves"),
        finding.get("cve_correlations"),
        (finding.get("threat_intel") or {}).get("cves") if isinstance(finding.get("threat_intel"), dict) else None,
    ):
        if isinstance(source, (list, tuple)):
            for item in source:
                _add(item)
        else:
            _add(source)
    return collected


class ThreatIntelCorrelator:
    """Correlates discovered assets, IPs, and vulnerabilities with external Threat Intel sources."""

    def __init__(self, enable_threat_intel: bool = True) -> None:
        self.enable_threat_intel = enable_threat_intel

    def correlate_cve(self, finding_category: str) -> list[str]:
        """Production CVE correlation.

        Category names are not CVEs. Historical example IDs live in
        ``NON_PRODUCTION_CATEGORY_CVE_EXAMPLES`` and are excluded here so
        EPSS/KEV cannot be attached to unrelated vulnerabilities.
        """
        del finding_category
        return []

    async def match_ioc_async(self, host_or_ip: str) -> dict[str, Any]:
        """Correlate host assets or target IPs with known threat indicators (MISP/VirusTotal/OTX).

        Queries active connectors (VirusTotal, AlienVault OTX, MISP) and combines
        their outputs to calculate reputation scores and attribution threat levels.
        """
        if not self.enable_threat_intel:
            return {"status": "disabled", "malicious": False, "score": 0}

        import os

        from src.intelligence.feeds.misp import MISPClient, MISPConfig
        from src.intelligence.feeds.otx import OTXClient, OTXConfig
        from src.intelligence.feeds.virustotal import VirusTotalClient, VirusTotalConfig

        host = str(host_or_ip or "").strip().lower()
        score = 0
        feed_sources = []
        intel_category = None
        attribution = None

        # 1. Query MISP Feed
        misp_key = os.environ.get("MISP_API_KEY")
        if not misp_key:
            logger.warning("MISP API key is missing. Skipping active MISP threat correlation.")
        else:
            try:
                misp_cfg = MISPConfig(api_key=misp_key)
                async with MISPClient(misp_cfg) as misp_client:
                    misp_res = await misp_client.check_ioc(host_or_ip)
                    if misp_res.get("matched"):
                        score = max(score, misp_res.get("reputation_score", 85))
                        feed_sources.append("MISP Feed")
                        intel_category = "active_c2_communication"
                        attribution = "APT-Unknown"
                try:
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter(
                        "threat_intel_queries_total",
                        "Threat intel queries",
                        labels={"feed": "misp", "status": "success"},
                    ).inc()
                except (ImportError, AttributeError):
                    logger.debug("Metrics tracking failed (MISP success)", exc_info=True)
            except Exception as e:
                logger.warning("MISP lookup failed: %s", e)
                try:
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter(
                        "threat_intel_queries_total",
                        "Threat intel queries",
                        labels={"feed": "misp", "status": "failed"},
                    ).inc()
                except (ImportError, AttributeError):
                    logger.debug("Metrics tracking failed (MISP failure)", exc_info=True)

        # 2. Query AlienVault OTX
        otx_key = os.environ.get("OTX_API_KEY")
        if otx_key:
            try:
                otx_cfg = OTXConfig(api_key=otx_key)
                async with OTXClient(otx_cfg) as otx_client:
                    indicator_type = indicator_type_for(host)
                    otx_res = await otx_client.get_indicator_details(indicator_type, host_or_ip)
                    if hasattr(otx_res, "pulses") and otx_res.pulses:
                        score = max(score, 75)
                        feed_sources.append("AlienVault OTX")
                        intel_category = "threat_pulse_match"
                try:
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter(
                        "threat_intel_queries_total",
                        "Threat intel queries",
                        labels={"feed": "otx", "status": "success"},
                    ).inc()
                except (ImportError, AttributeError):
                    logger.debug("Metrics tracking failed (OTX success)", exc_info=True)
            except Exception as e:
                logger.warning("OTX lookup failed: %s", e)
                try:
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter(
                        "threat_intel_queries_total",
                        "Threat intel queries",
                        labels={"feed": "otx", "status": "failed"},
                    ).inc()
                except (ImportError, AttributeError):
                    logger.debug("Metrics tracking failed (OTX failure)", exc_info=True)

        # 3. Query VirusTotal
        from src.intelligence.feeds.virustotal import resolve_virustotal_api_key

        vt_key = resolve_virustotal_api_key()
        if vt_key:
            try:
                vt_cfg = VirusTotalConfig(api_key=vt_key)
                async with VirusTotalClient(vt_cfg) as vt_client:
                    if is_ip(host):
                        vt_res = await vt_client.get_ip_report(host_or_ip)
                    else:
                        vt_res = await vt_client.get_domain_report(host_or_ip)
                    if vt_res and getattr(vt_res, "malicious_count", 0) > 0:
                        score = max(score, min(99, 50 + getattr(vt_res, "malicious_count", 0) * 10))
                        feed_sources.append("VirusTotal")
                try:
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter(
                        "threat_intel_queries_total",
                        "Threat intel queries",
                        labels={"feed": "virustotal", "status": "success"},
                    ).inc()
                except (ImportError, AttributeError):
                    logger.debug("Metrics tracking failed (VT success)", exc_info=True)
            except Exception as e:
                logger.warning("VirusTotal lookup failed: %s", e)
                try:
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter(
                        "threat_intel_queries_total",
                        "Threat intel queries",
                        labels={"feed": "virustotal", "status": "failed"},
                    ).inc()
                except (ImportError, AttributeError):
                    logger.debug("Metrics tracking failed (VT failure)", exc_info=True)

        # Local simulation fallback is *only* honoured when the
        # operator has explicitly enabled test mode. Otherwise a
        # production host with "malicious" in its name would never
        # produce a false positive.
        if _is_test_mode():
            suspicious_keywords = {"malicious", "botnet", "phishing", "c2-server", "tor-exit"}
            malicious_keyword = any(kw in host for kw in suspicious_keywords)
            if malicious_keyword and score == 0:
                score = 85
                feed_sources = ["VirusTotal", "AlienVault OTX", "MISP Feed 42"]
                intel_category = "active_c2_communication"
                attribution = "APT-Unknown"
            elif ("sandbox" in host or "example" in host) and score == 0:
                score = 15
                feed_sources = ["MISP Feed 01 (Sandbox Cache)"]
                intel_category = "test_environment"

        return {
            "status": "active",
            "host": host_or_ip,
            "malicious": score > 50,
            "reputation_score": score,
            "intel_category": intel_category,
            "matched_feeds": feed_sources,
            "threat_actor_attribution": attribution,
        }

    def match_ioc(self, host_or_ip: str) -> dict[str, Any]:
        """Synchronous threat correlation fallback.

        Acts as a local cache/matcher. Simulation fallbacks require
        ``PIPELINE_THREAT_INTEL_TEST_MODE=1`` so production traffic
        never inherits fake flags.
        """
        host = str(host_or_ip or "").strip().lower()

        is_testing = _is_test_mode()
        suspicious_keywords = {"malicious", "botnet", "phishing", "c2-server", "tor-exit"}
        malicious = any(kw in host for kw in suspicious_keywords) if is_testing else False

        score = 0
        feed_sources = []
        intel_category = None

        if malicious:
            score = 85
            feed_sources = ["VirusTotal", "AlienVault OTX", "MISP Feed 42"]
            intel_category = "active_c2_communication"
        elif is_testing and ("sandbox" in host or "example" in host):
            score = 15
            feed_sources = ["MISP Feed 01 (Sandbox Cache)"]
            intel_category = "test_environment"

        return {
            "status": "active",
            "host": host_or_ip,
            "malicious": malicious or score > 50,
            "reputation_score": score,
            "intel_category": intel_category,
            "matched_feeds": feed_sources,
            "threat_actor_attribution": "APT-Unknown" if malicious else None,
        }

    # ------------------------------------------------------------------
    # CVE / EPSS / KEV enrichment
    # ------------------------------------------------------------------

    def enrich_findings_with_intel(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Synchronous enrichment: CVE map + EPSS + CISA KEV."""
        enriched: list[dict[str, Any]] = []
        for finding in findings:
            f_copy = dict(finding)
            cves = explicit_cves_from_finding(f_copy)

            # EPSS / CISA KEV only for CVEs already on the finding.
            for cve in cves:
                self._attach_epss(f_copy, cve)
                self._attach_cisa_kev(f_copy, cve)
            if cves:
                logger.info(
                    "ThreatIntel: Enriched finding %s with explicit CVEs: %s",
                    f_copy.get("id"),
                    cves,
                )
            enriched.append(f_copy)
        return enriched

    async def enrich_findings_with_intel_async(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Async enrichment: CVE map + IOC feeds + EPSS + CISA KEV."""
        enriched = []
        for finding in findings:
            f_copy = dict(finding)
            cat = f_copy.get("category") or f_copy.get("type") or ""
            cves = self.correlate_cve(cat)
            f_copy["cve_correlations"] = cves

            target_url = f_copy.get("url")
            if target_url:
                from urllib.parse import urlparse

                host = urlparse(str(target_url)).netloc
                if host:
                    try:
                        ioc_match = await self.match_ioc_async(host)
                        if ioc_match.get("malicious"):
                            f_copy.setdefault("threat_intel", {})["ioc_correlation"] = ioc_match
                            logger.info(
                                "ThreatIntel: Correlated finding target '%s' to threat feeds!",
                                host,
                            )
                    except Exception as e:
                        logger.debug("Failed to match finding target against IoC feeds: %s", e)

            for cve in cves:
                self._attach_epss(f_copy, cve)
                self._attach_cisa_kev(f_copy, cve)

            if cves:
                logger.info(
                    "ThreatIntel: Enriched finding %s with CVEs: %s",
                    f_copy.get("id"),
                    cves,
                )
            enriched.append(f_copy)
        return enriched

    @staticmethod
    def _attach_epss(finding: dict[str, Any], cve: str) -> None:
        try:
            from src.intelligence.risk.epss import get_default_epss_client
        except (ImportError, AttributeError):
            return
        try:
            score = get_default_epss_client().lookup(cve)
        except (TypeError, ValueError, KeyError) as exc:
            logger.debug("EPSS lookup failed for %s: %s", cve, exc)
            return
        if score is None:
            return
        threat_intel = dict(finding.get("threat_intel") or {})
        records = list(threat_intel.get("epss_records") or [])
        records.append(score.to_dict())
        threat_intel["epss_records"] = records
        threat_intel["epss_score"] = max(
            float(threat_intel.get("epss_score", 0.0) or 0.0), score.epss_score
        )
        threat_intel["epss_percentile"] = max(
            float(threat_intel.get("epss_percentile", 0.0) or 0.0), score.percentile
        )
        finding["threat_intel"] = threat_intel

    @staticmethod
    def _attach_cisa_kev(finding: dict[str, Any], cve: str) -> None:
        try:
            from src.intelligence.risk.cisa_kev import get_default_cisa_kev_client
        except (ImportError, AttributeError):
            return
        try:
            record = get_default_cisa_kev_client().lookup(cve)
        except (TypeError, ValueError, KeyError) as exc:
            logger.debug("CISA KEV lookup failed for %s: %s", cve, exc)
            return
        if record is None:
            return
        threat_intel = dict(finding.get("threat_intel") or {})
        threat_intel["cisa_kev"] = True
        records = list(threat_intel.get("cisa_kev_records") or [])
        records.append(record.to_dict())
        threat_intel["cisa_kev_records"] = records
        if record.due_date_ts:
            current = threat_intel.get("cisa_kev_due_ts")
            if not current or record.due_date_ts < float(current):
                threat_intel["cisa_kev_due_ts"] = record.due_date_ts
        finding["threat_intel"] = threat_intel
