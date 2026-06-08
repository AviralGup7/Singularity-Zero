"""CISA Known Exploited Vulnerabilities (KEV) catalogue enrichment.

CISA publishes a JSON catalogue of CVEs that are known to be
actively exploited in the wild. The list is small (a few thousand
entries at any given time) and is republished multiple times per
day, so we cache the full catalogue in memory with a configurable
TTL.

The catalogue URL is::

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 hours
DEFAULT_HTTP_TIMEOUT_SECONDS = 8.0
DEFAULT_USER_AGENT = "cyber-security-test-pipeline/1.0 (+cisa-kev)"


@dataclass
class KEVRecord:
    """A single entry in the CISA KEV catalogue."""

    cve: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    date_added: str = ""
    due_date: str = ""
    short_description: str = ""
    required_action: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def due_date_ts(self) -> float:
        if not self.due_date:
            return 0.0
        try:
            import datetime

            return datetime.datetime.fromisoformat(self.due_date).timestamp()
        except ValueError:
            return 0.0

    def days_until_due(self, now: float | None = None) -> float | None:
        if not self.due_date_ts:
            return None
        return (self.due_date_ts - (now or time.time())) / 86400.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "vendor": self.vendor,
            "product": self.product,
            "name": self.name,
            "date_added": self.date_added,
            "due_date": self.due_date,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "days_until_due": self.days_until_due(),
        }


class CISAKEVClient:
    """Fetch + cache the CISA KEV catalogue.

    The catalogue is fetched on first use and then re-fetched when
    older than ``cache_ttl_seconds``. If the network is unreachable,
    the client keeps serving the last successful payload.
    """

    def __init__(
        self,
        *,
        url: str | None = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.url = url or os.environ.get("CISA_KEV_URL", DEFAULT_KEV_URL)
        self.timeout = float(timeout)
        self.cache_ttl_seconds = float(cache_ttl_seconds)
        self.user_agent = user_agent
        self._lock = threading.RLock()
        self._catalogue: dict[str, KEVRecord] = {}
        self._last_fetched: float = 0.0

    # -- public --------------------------------------------------------

    def is_known_exploited(self, cve: str) -> bool:
        cve_id = self._normalise_cve(cve)
        if not cve_id:
            return False
        self._ensure_fresh()
        with self._lock:
            return cve_id in self._catalogue

    def lookup(self, cve: str) -> KEVRecord | None:
        cve_id = self._normalise_cve(cve)
        if not cve_id:
            return None
        self._ensure_fresh()
        with self._lock:
            return self._catalogue.get(cve_id)

    def all_records(self) -> list[KEVRecord]:
        self._ensure_fresh()
        with self._lock:
            return list(self._catalogue.values())

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        cves = self._extract_cves(finding)
        if not cves:
            return finding
        matched: list[dict[str, Any]] = []
        earliest_due: float | None = None
        for cve in cves:
            record = self.lookup(cve)
            if record is None:
                continue
            matched.append(record.to_dict())
            due_ts = record.due_date_ts
            if due_ts and (earliest_due is None or due_ts < earliest_due):
                earliest_due = due_ts
        if not matched:
            return finding
        finding = dict(finding)
        threat_intel = dict(finding.get("threat_intel") or {})
        threat_intel["cisa_kev"] = True
        threat_intel["cisa_kev_records"] = matched
        if earliest_due is not None:
            threat_intel["cisa_kev_due_ts"] = earliest_due
        finding["threat_intel"] = threat_intel
        return finding

    def enrich_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.enrich_finding(f) for f in findings]

    # -- internals -----------------------------------------------------

    def _ensure_fresh(self) -> None:
        with self._lock:
            stale = (time.time() - self._last_fetched) > self.cache_ttl_seconds
            empty = not self._catalogue
        if not (stale or empty):
            return
        if self._network_disabled():
            return
        self._refresh()

    def _refresh(self) -> None:
        try:
            request = urllib.request.Request(  # noqa: S310
                self.url, headers={"User-Agent": self.user_agent, "Accept": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            logger.debug("CISAKEVClient: catalogue fetch failed: %s", exc)
            return
        self._update_catalogue(payload)

    def _update_catalogue(self, payload: dict[str, Any]) -> None:
        records = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return
        new_catalogue: dict[str, KEVRecord] = {}
        for entry in records:
            if not isinstance(entry, dict):
                continue
            cve = self._normalise_cve(entry.get("cveID", ""))
            if not cve:
                continue
            new_catalogue[cve] = KEVRecord(
                cve=cve,
                vendor=str(entry.get("vendorProject", "")),
                product=str(entry.get("product", "")),
                name=str(entry.get("vulnerabilityName", "")),
                date_added=str(entry.get("dateAdded", "")),
                due_date=str(entry.get("dueDate", "")),
                short_description=str(entry.get("shortDescription", "")),
                required_action=str(entry.get("requiredAction", "")),
                raw=dict(entry),
            )
        with self._lock:
            self._catalogue = new_catalogue
            self._last_fetched = time.time()
        logger.info("CISAKEVClient: refreshed catalogue with %d records", len(new_catalogue))

    @staticmethod
    def _normalise_cve(cve: str) -> str:
        text = str(cve or "").strip().upper()
        if not text:
            return ""
        if not text.startswith("CVE-"):
            return ""
        return text

    def _extract_cves(self, finding: dict[str, Any]) -> list[str]:
        cves: list[str] = []
        for source in (
            finding.get("cve_correlations"),
            (finding.get("threat_intel") or {}).get("cves"),
        ):
            if not source:
                continue
            for item in source:
                norm = self._normalise_cve(item)
                if norm and norm not in cves:
                    cves.append(norm)
        if not cves and finding.get("category"):
            try:
                from src.intelligence.threat_intel import ThreatIntelCorrelator

                cves.extend(
                    ThreatIntelCorrelator().correlate_cve(str(finding.get("category", "")))
                )
            except Exception:  # noqa: BLE001
                pass
        return [c for c in cves if c]

    def _network_disabled(self) -> bool:
        flag = os.environ.get("PIPELINE_OFFLINE", "").strip().lower()
        return flag in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_client: CISAKEVClient | None = None


def get_default_cisa_kev_client() -> CISAKEVClient:
    global _default_client
    with _default_lock:
        if _default_client is None:
            _default_client = CISAKEVClient()
        return _default_client


def reset_default_cisa_kev_client() -> None:
    global _default_client
    with _default_lock:
        _default_client = None


__all__ = [
    "CISAKEVClient",
    "DEFAULT_CACHE_TTL_SECONDS",
    "DEFAULT_KEV_URL",
    "KEVRecord",
    "get_default_cisa_kev_client",
    "reset_default_cisa_kev_client",
]
