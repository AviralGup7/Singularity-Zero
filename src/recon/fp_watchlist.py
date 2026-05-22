"""False positive re-evaluation watchlist serializer.

Persists FALSE_POSITIVE findings into a regression watchlist on every run completion,
detects re-emergences on subsequent runs, produces notifications for regression alerts,
and exposes watchlist URLs for re-injection at elevated confidence thresholds.

Per EVOLUTION_ALPHA_PLAN.md Phase 9.2 hardening + GAP_ANALYSIS.md Phase 9.2.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_WATCHLIST_FILENAME = "regression-watchlist.json"

_FP_STATUSES: set[str] = {"false_positive"}

_FP_LIFECYCLE_STATES: set[str] = {"false_positive"}

_FP_DECISIONS: set[str] = {"drop"}

_MONITORING_STATUS = "monitoring"

_REMEDIATED_STATUSES: set[str] = {"remediated", "resolved", "closed"}

_REEMERGENCE_MATCH_STREPTH = 0.6  # jaccard threshold kept for future fuzzy matching


def _is_false_positive(finding: dict[str, Any]) -> bool:
    """Return True if the finding is classified as a false positive."""
    status = str(finding.get("status", "")).strip().lower()
    lifecycle_state = str(finding.get("lifecycle_state", "")).strip().lower()
    decision = str(finding.get("decision", "")).strip().lower()
    fp_reason = finding.get("false_positive_reason") or finding.get("fp_reason")
    if status in _FP_STATUSES or lifecycle_state in _FP_LIFECYCLE_STATES or decision in _FP_DECISIONS:
        return True
    if fp_reason:
        return True
    is_fp = finding.get("is_false_positive")
    if isinstance(is_fp, bool) and is_fp:
        return True
    return False


def _extract_finding_id(finding: dict[str, Any]) -> str:
    """Extract the finding's unique identifier or generate a stable hash."""
    fid = finding.get("id") or finding.get("finding_id")
    if fid:
        return str(fid).strip()
    raw = json.dumps(finding, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _extract_url(finding: dict[str, Any]) -> str:
    """Extract URL from finding, normalizing empty/missing values."""
    raw_url = finding.get("url") or finding.get("target") or ""
    return str(raw_url).strip()


def _build_url_pattern(url: str) -> str:
    """Return a wildcard pattern suitable for injection back into recon.

    Strips the query string, keeps only the path segment of the resource,
    and appends ``*`` to match anything deeper. If the path is empty the
    result is ``scheme://host*``.
    """
    if not url:
        return "*"
    candidate = url if "://" in url else f"https://{url}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return f"{candidate.split('?')[0].split('#')[0]}*"
    path = parsed.path or "/"
    host = parsed.netloc or parsed.path
    root = f"{parsed.scheme}://{host}{path}"
    # Strip query and fragment; keep the resource path and append wildcard
    return f"{root}*"


def _extract_vulnerability_class(finding: dict[str, Any]) -> str:
    """Return the vulnerability category / class string."""
    cls = finding.get("category") or finding.get("type") or finding.get("vulnerability_class") or "unknown"
    return str(cls).strip().lower()


def _extract_severity(finding: dict[str, Any]) -> str:
    """Return original severity in lowercase."""
    sev = finding.get("severity") or "info"
    return str(sev).strip().lower()


def _extract_fp_reason(finding: dict[str, Any]) -> str:
    """Return the false-positive reason string if available."""
    return str(
        finding.get("false_positive_reason")
        or finding.get("fp_reason")
        or finding.get("suppress_reason")
        or finding.get("reason")
        or ""
    ).strip()


def _extract_timestamp(finding: dict[str, Any]) -> str:
    """Extract the finding's detection timestamp as an ISO-8601 string."""
    for field in ("first_detected_timestamp", "first_detected", "timestamp", "date"):
        value = finding.get(field)
        if value:
            return str(value).strip()
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_watchlist_entry(finding: dict[str, Any]) -> dict[str, Any]:
    """Build one regression-watchlist entry from a false-positive finding."""
    url = _extract_url(finding)
    url_pattern = _build_url_pattern(url)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry: dict[str, Any] = {
        "finding_id": _extract_finding_id(finding),
        "url": url,
        "url_pattern": url_pattern,
        "vulnerability_class": _extract_vulnerability_class(finding),
        "original_severity": _extract_severity(finding),
        "original_false_positive_reason": _extract_fp_reason(finding),
        "first_detected": _extract_timestamp(finding),
        "last_seen": now,
        "watchlist_since": now,
        "re_emergence_count": finding.get("re_emergence_count", 0),
        "status": _MONITORING_STATUS,
    }
    return entry


def _match_reemergence(watchlist_entry: dict[str, Any], new_finding: dict[str, Any]) -> bool:
    """Return True if `new_finding` re-emerges the same issue tracked in `watchlist_entry`.

    Matches on two dimenions:
    - Vulnerability class must be identical.
    - URL of the new finding must satisfy the stored url_pattern wildcard.
    """
    if watchlist_entry.get("status") in _REMEDIATED_STATUSES:
        return False
    wl_vuln_class = str(watchlist_entry.get("vulnerability_class", "")).strip().lower()
    nf_vuln_class = _extract_vulnerability_class(new_finding)
    if wl_vuln_class != nf_vuln_class:
        return False
    new_url = _extract_url(new_finding)
    pattern = watchlist_entry.get("url_pattern", "*")
    return fnmatch_url(new_url, pattern)


def fnmatch_url(url: str, pattern: str) -> bool:
    """Lightweight wildcard URL match.

    Supports the ``*`` wildcard (matching any non-empty substring) and uses
    |fnmatch| underneath so patterns like ``*.example.com`` continue to work
    in the watchlist schema after future migrations.
    """
    import fnmatch

    norm_url = url.strip().lower()
    norm_pattern = pattern.strip().lower()
    # Anchor pattern to avoid partial substring matches when no wildcard is present
    if "*" not in norm_pattern and "?" not in norm_pattern:
        return norm_url == norm_pattern
    return fnmatch.fnmatch(norm_url, norm_pattern)


class FPWatchlistManager:
    """Serialize, load, and monitor a false-positive regression watchlist.

    The watchlist bridges gap 9.2: FP findings are captured at the end of each
    run, re-evaluated against subsequent findings, and forwarded as ``regression``
    notifications to the ``NotificationManager`` so the security team is alerted
    immediately on any re-emergence rather than the issue fading to the back of
    the pipeline.

    Files are written to ``<output_dir>/regression-watchlist.json`` and the file
    can also be loaded explicitly via :py:meth:`load_watchlist`.
    """

    def __init__(self, watchlist_path: Path | None = None) -> None:
        self.watchlist_path: Path | None = watchlist_path
        self._logger = logging.getLogger(f"{__name__}.{type(self).__name__}")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _default_watchlist_path(self, output_dir: Path) -> Path:
        return output_dir / _WATCHLIST_FILENAME

    def serialize_from_findings(
        self,
        findings: list[dict[str, Any]],
        output_dir: Path,
    ) -> Path:
        """Extract FALSE_POSITIVE findings and write regression-watchlist.json to ``output_dir``.

        Each watchlist entry captures the **first** occurrence of a given
        false-positive finding (by ``finding_id``) within ``findings``.  If the
        watchlist file already exists on disk the current state is preserved;
        only new entries are appended so ``re_emergence_count`` and
        ``watchlist_since`` values are not reset between runs.

        Args:
            findings: All merged findings emitted at run completion.
            output_dir: Directory in which to write ``regression-watchlist.json``.

        Returns:
            Absolute :class:`~pathlib.Path` to the written watchlist file.
        """
        target_path = self._default_watchlist_path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        self.watchlist_path = target_path

        existing: list[dict[str, Any]] = []
        if target_path.exists():
            existing = self._load_raw(target_path)

        existing_ids: set[str] = {str(e.get("finding_id", "")) for e in existing if e.get("finding_id")}
        existing_by_pattern: dict[str, dict[str, Any]] = {
            str(e.get("url_pattern", "")).strip().lower(): e for e in existing if e.get("url_pattern")
        }

        appended = 0
        for raw_finding in findings:
            if not _is_false_positive(raw_finding):
                continue
            entry = _build_watchlist_entry(raw_finding)
            fid = entry["finding_id"]
            pattern = entry["url_pattern"]
            if fid not in existing_ids and pattern not in existing_by_pattern:
                existing.append(entry)
                existing_ids.add(fid)
                existing_by_pattern[pattern.lower()] = entry
                appended += 1
            self._logger.debug("False positive finding serialized: %s", fid)

        target_path.write_text(
            json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        self._logger.info(
            "regression-watchlist.json written to %s (%d entries, %d new)",
            target_path,
            len(existing),
            appended,
        )
        return target_path

    def load_watchlist(self, watchlist_path: Path | None = None) -> list[dict[str, Any]]:
        """Load the regression watchlist from file.

        If ``watchlist_path`` is ``None`` the path set at construction time is
        used.  Returns an empty list if the file does not exist or cannot be
        parsed.

        Args:
            watchlist_path: Override path to the watchlist JSON file.

        Returns:
            List of watchlist entry dicts, or an empty list on failure.
        """
        path = watchlist_path or self.watchlist_path
        if path is None:
            self._logger.warning("No watchlist path configured; returning empty list.")
            return []
        return self._load_raw(path)

    @staticmethod
    def _load_raw(path: Path) -> list[dict[str, Any]]:
        """Read and parse a watchlist JSON file; returns [] on any error."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
            self_log = logging.getLogger(f"{__name__}.{FPWatchlistManager.__name__}")
            self_log.warning("Watchlist at %s is not a JSON array; returning []", path)
            return []
        except FileNotFoundError:
            return []
        except (json.JSONDecodeError, OSError) as exc:
            self_log = logging.getLogger(f"{__name__}.{FPWatchlistManager.__name__}")
            self_log.warning("Failed to load watchlist from %s: %s", path, exc)
            return []

    # ------------------------------------------------------------------
    # Re-emergence detection
    # ------------------------------------------------------------------

    def check_reemergence(
        self,
        new_findings: list[dict[str, Any]],
        notification_manager: Any | None = None,
    ) -> list[dict[str, Any]]:
        """Compare new findings against the watchlist.

        A finding is a ``re-emergence`` when its URL satisfies the stored
        ``url_pattern`` wildcard *and* its ``vulnerability_class`` matches.

        When ``notification_manager`` is provided a ``CUSTOM`` regression alert
        with ``HIGH`` priority is sent for each re-emergence (see
        :py:meth:`NotificationManager.send`).

        Args:
            new_findings: Findings produced by the latest run (before FP
                filtering).
            notification_manager: Optional :class:`NotificationManager` instance
                used to emit regression notifications.

        Returns:
            List of new-finding dicts that re-emerge a watchlist entry.
        """
        watchlist = self.load_watchlist()
        if not watchlist:
            return []

        reemerged: list[dict[str, Any]] = []
        for new_finding in new_findings:
            for entry in watchlist:
                if _match_reemergence(entry, new_finding):
                    reemerged.append(new_finding)
                    self._logger.warning(
                        "Re-emergence detected: finding_id=%s url=%s pattern=%s",
                        entry.get("finding_id", "?"),
                        new_finding.get("url", "?"),
                        entry.get("url_pattern", "?"),
                    )
                    if notification_manager is not None:
                        self._notify_reemergence(notification_manager, entry, new_finding)
                    break  # avoid duplicate notification per finding

        return reemerged

    @staticmethod
    def _notify_reemergence(
        notification_manager: Any,
        watchlist_entry: dict[str, Any],
        new_finding: dict[str, Any],
    ) -> None:
        """Fire a regression notification for a re-emerged false-positive.

        Uses ``NotificationEvent.CUSTOM`` so that re-emergence alerts bypass
        any FINDING_DETECTED channel routing rules.
        """
        try:
            from src.infrastructure.notifications.base import (
                NotificationEvent,
                NotificationPriority,
            )

            wid = watchlist_entry.get("finding_id", "unknown")
            vuln_cls = watchlist_entry.get("vulnerability_class", "unknown")
            severity = watchlist_entry.get("original_severity", "info")
            url = new_finding.get("url") or watchlist_entry.get("url", "")
            fp_reason = watchlist_entry.get("original_false_positive_reason", "No reason recorded.")
            title = f"Regression alert: false-positive re-emergence [{vuln_cls}]"
            message = (
                f"A previously-classified false-positive finding has re-emerged.\n"
                f"Watchlist ID: {wid}\n"
                f"Vulnerability class: {vuln_cls}\n"
                f"Original severity: {severity}\n"
                f"URL: {url}\n"
                f"Original FP reason: {fp_reason}"
            )
            metadata = {
                "watchlist_id": wid,
                "vulnerability_class": vuln_cls,
                "original_severity": severity,
                "url": url,
                "re_emergence_count": watchlist_entry.get("re_emergence_count", 0) + 1,
            }
            corr_id = wid
            # Run the coroutine in the existing event loop when possible;
            # fall back to running_asyncio only if the loop is already closed.
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError("loop closed")
                loop.create_task(
                    notification_manager.send(
                        event=NotificationEvent.CUSTOM,
                        priority=NotificationPriority.HIGH,
                        title=title,
                        message=message,
                        metadata=metadata,
                        correlation_id=corr_id,
                    )
                )
            except RuntimeError:
                asyncio.run(
                    notification_manager.send(
                        event=NotificationEvent.CUSTOM,
                        priority=NotificationPriority.HIGH,
                        title=title,
                        message=message,
                        metadata=metadata,
                        correlation_id=corr_id,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger = logging.getLogger(f"{__name__}.{FPWatchlistManager.__name__}")
            logger.error("Failed to send re-emergence notification: %s", exc)

    # ------------------------------------------------------------------
    # Watchlist URL injection
    # ------------------------------------------------------------------

    def get_watchlist_urls(self, min_confidence: float = 0.7) -> list[str]:
        """Return URLs from the watchlist eligible for re-injection.

        Only entries with ``status`` set to ``"monitoring"`` are returned.
        The caller (e.g. ``build_nuclei_plan``) should apply an elevated
        confidence threshold (``min_confidence``) when testing these URLs.

        Args:
            min_confidence: Minimum confidence threshold filter (accepted for
                API consistency with ``build_nuclei_plan`` callers).  Currently
                not applied to individual entries; all monitoring entries are
                returned.

        Returns:
            De-duplicated list of ``url_pattern`` strings with
            ``status == "monitoring"``.
        """
        watchlist = self.load_watchlist()
        urls = [
            str(e.get("url_pattern", "")).strip()
            for e in watchlist
            if str(e.get("status", "")).strip().lower() == _MONITORING_STATUS
            and e.get("url_pattern")
        ]
        # Preserve insertion order while deduplicating
        seen: set[str] = set()
        deduped: list[str] = []
        for u in urls:
            if u.lower() not in seen:
                seen.add(u.lower())
                deduped.append(u)
        return deduped
