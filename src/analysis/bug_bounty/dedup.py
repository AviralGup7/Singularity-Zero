from __future__ import annotations
import logging
"""Bug bounty finding deduplication.

Loads previously submitted findings from a JSON store and fingerprints
new findings to detect duplicates before submission.
"""


import hashlib
import json
from pathlib import Path
from typing import Any


class FindingDedup:
    def __init__(self, submitted_findings_path: str) -> None:
        self.submitted_findings_path = Path(submitted_findings_path)
        self._submitted: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.submitted_findings_path.exists():
            self._submitted = {}
            return
        try:
            raw = self.submitted_findings_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    fp = self.fingerprint_finding(item) if isinstance(item, dict) else str(item)
                    self._submitted[fp] = item if isinstance(item, dict) else {"raw": str(item)}
            elif isinstance(data, dict):
                self._submitted = {str(k): v for k, v in data.items()}
        except (OSError, json.JSONDecodeError):
            self._submitted = {}

    def _save(self) -> None:
        try:
            self.submitted_findings_path.parent.mkdir(parents=True, exist_ok=True)
            self.submitted_findings_path.write_text(
                json.dumps(self._submitted, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            logging.warning("Operation failed in dedup.py: %s", exc, exc_info=True)  # noqa: BLE001

    def fingerprint_finding(self, finding: dict[str, Any]) -> str:
        tool = str(finding.get("tool") or finding.get("source") or "unknown").strip().lower()
        target = str(
            finding.get("target_url")
            or finding.get("affected_url")
            or finding.get("url")
            or "unknown"
        ).strip().lower()
        vuln_type = str(finding.get("vuln_type") or finding.get("category") or finding.get("title") or "unknown").strip().lower()
        affected = str(finding.get("affected_url") or finding.get("url") or "unknown").strip().lower()
        raw = "|".join([tool, target, vuln_type, affected])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, finding: dict[str, Any]) -> tuple[bool, str | None]:
        fp = self.fingerprint_finding(finding)
        if fp in self._submitted:
            existing = self._submitted[fp]
            report_id = existing.get("report_id") or existing.get("id") or existing.get("title")
            return True, str(report_id) if report_id is not None else None
        return False, None

    def mark_submitted(self, finding: dict[str, Any], report_id: str | None = None) -> None:
        fp = self.fingerprint_finding(finding)
        entry = dict(finding)
        if report_id:
            entry["report_id"] = report_id
        self._submitted[fp] = entry
        self._save()
