"""EPSS (Exploit Prediction Scoring System) enrichment.

EPSS is a FIRST-maintained daily score that estimates the
probability a CVE will be exploited in the wild over the next 30
days. EPSS complements CVSS by answering "how dangerous is this
vulnerability *in practice*?" rather than "how bad is the worst
case?".

The data is fetched from::

    https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX

EPSS scores are between 0.0 and 1.0. We do not block on a missing
or stale fetch - all functions return ``None`` and let the caller
fall back to other signals.

Local cache: 24 hours per CVE by default, configurable.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
DEFAULT_HTTP_TIMEOUT_SECONDS = 6.0
DEFAULT_USER_AGENT = "cyber-security-test-pipeline/1.0 (+epss)"


@dataclass
class EPSSScore:
    """An EPSS record for a single CVE."""

    cve: str
    epss_score: float  # 0.0 - 1.0
    percentile: float  # 0.0 - 1.0
    fetched_at: float
    source: str = "first.org"
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "epss_score": round(self.epss_score, 4),
            "percentile": round(self.percentile, 4),
            "fetched_at": self.fetched_at,
            "source": self.source,
            "age_seconds": max(0.0, time.time() - self.fetched_at),
        }

    def is_stale(self, ttl: float = DEFAULT_CACHE_TTL_SECONDS) -> bool:
        return (time.time() - self.fetched_at) > ttl


class EPSSClient:
    """Fetch + cache EPSS scores from FIRST.org.

    The client is dependency-free (uses ``urllib.request``) and
    threadsafe. A simple in-memory cache is included; a persistent
    cache can be plugged in via ``cache_backend`` (a mapping of
    CVE -> EPSSScore-like dict).
    """

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        cache_backend: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.endpoint = endpoint or os.environ.get("EPSS_API_ENDPOINT", DEFAULT_EPSS_ENDPOINT)
        self.timeout = float(timeout)
        self.cache_ttl_seconds = float(cache_ttl_seconds)
        self.user_agent = user_agent
        self._lock = threading.RLock()
        self._memory_cache: dict[str, EPSSScore] = {}
        self._persistent_cache = cache_backend

    # -- public --------------------------------------------------------

    def lookup(self, cve: str) -> EPSSScore | None:
        """Return an EPSS score for a single CVE, fetching as needed."""
        cve_id = self._normalise_cve(cve)
        if not cve_id:
            return None

        with self._lock:
            cached = self._memory_cache.get(cve_id)
            if cached and not cached.is_stale(self.cache_ttl_seconds):
                return cached
            persistent = self._load_persistent(cve_id)
            if persistent and not persistent.is_stale(self.cache_ttl_seconds):
                self._memory_cache[cve_id] = persistent
                return persistent
            # Stale persistent cache: populate memory so callers
            # get a value even when network is disabled.
            if persistent is not None:
                self._memory_cache[cve_id] = persistent

        # Avoid hammering the upstream API when offline. If the
        # environment explicitly disables network access, skip.
        if self._network_disabled():
            return self._memory_cache.get(cve_id)

        fetched = self._fetch_remote(cve_id)
        if fetched is None:
            return self._memory_cache.get(cve_id)
        with self._lock:
            self._memory_cache[cve_id] = fetched
        self._save_persistent(fetched)
        return fetched

    def lookup_many(self, cves: Iterable[str]) -> dict[str, EPSSScore | None]:
        normalised = {self._normalise_cve(cve) for cve in cves if cve}
        return {cve: self.lookup(cve) for cve in normalised}

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Attach ``threat_intel.epss`` to a finding if CVEs are present."""
        cves = self._extract_cves(finding)
        if not cves:
            return finding
        records: list[dict[str, Any]] = []
        for cve in cves:
            score = self.lookup(cve)
            if score is None:
                continue
            records.append(score.to_dict())
        if not records:
            return finding
        finding = dict(finding)
        threat_intel = dict(finding.get("threat_intel") or {})
        threat_intel["epss"] = records
        # Surface the highest EPSS score on the finding for the
        # severity model to consume.
        threat_intel["epss_score"] = max(r["epss_score"] for r in records)
        threat_intel["epss_percentile"] = max(r["percentile"] for r in records)
        finding["threat_intel"] = threat_intel
        return finding

    def enrich_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.enrich_finding(f) for f in findings]

    # -- internals -----------------------------------------------------

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
        # Fall back to category-based CVE hints from the threat intel
        # correlator. ``correlate_cve`` is called lazily to avoid
        # circular imports.
        if not cves and finding.get("category"):
            try:
                from src.intelligence.threat_intel import ThreatIntelCorrelator

                cves.extend(ThreatIntelCorrelator().correlate_cve(str(finding.get("category", ""))))
            except Exception:  # noqa: BLE001, S110
                pass
        return [c for c in cves if c]

    def _fetch_remote(self, cve: str) -> EPSSScore | None:
        url = f"{self.endpoint}?cve={cve}"
        try:
            request = urllib.request.Request(  # noqa: S310
                url,
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310  # nosec
                payload = json.loads(response.read().decode("utf-8"))
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:
            logger.debug("EPSSClient: %s fetch failed: %s", cve, exc)
            return None
        return self._parse_payload(cve, payload)

    @staticmethod
    def _parse_payload(cve: str, payload: dict[str, Any]) -> EPSSScore | None:
        records = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(records, list) or not records:
            return None
        record = records[0]
        try:
            score = float(record.get("epss", 0.0))
            percentile = float(record.get("percentile", 0.0))
        except (TypeError, ValueError):
            return None
        return EPSSScore(
            cve=cve,
            epss_score=max(0.0, min(1.0, score)),
            percentile=max(0.0, min(1.0, percentile)),
            fetched_at=time.time(),
            source="first.org",
            raw=dict(record),
        )

    def _network_disabled(self) -> bool:
        flag = os.environ.get("PIPELINE_OFFLINE", "").strip().lower()
        return flag in {"1", "true", "yes", "on"}

    def _load_persistent(self, cve: str) -> EPSSScore | None:
        if not self._persistent_cache:
            return None
        payload = self._persistent_cache.get(cve)
        if not payload or not isinstance(payload, dict):
            return None
        try:
            return EPSSScore(
                cve=cve,
                epss_score=float(payload.get("epss_score", 0.0)),
                percentile=float(payload.get("percentile", 0.0)),
                fetched_at=float(payload.get("fetched_at", 0.0)),
                source=str(payload.get("source", "cache")),
                raw=dict(payload.get("raw", {}) or {}),
            )
        except (TypeError, ValueError):
            return None

    def _save_persistent(self, score: EPSSScore) -> None:
        if not self._persistent_cache:
            return
        self._persistent_cache[score.cve] = score.to_dict()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_client: EPSSClient | None = None


def get_default_epss_client() -> EPSSClient:
    global _default_client
    with _default_lock:
        if _default_client is None:
            _default_client = EPSSClient()
        return _default_client


def reset_default_epss_client() -> None:
    global _default_client
    with _default_lock:
        _default_client = None


__all__ = [
    "DEFAULT_CACHE_TTL_SECONDS",
    "DEFAULT_EPSS_ENDPOINT",
    "EPSSClient",
    "EPSSScore",
    "get_default_epss_client",
    "reset_default_epss_client",
]
