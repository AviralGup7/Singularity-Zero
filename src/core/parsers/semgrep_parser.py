"""Deterministic parser for Semgrep JSON output into pipeline Finding objects.

Semgrep JSON typically contains a top-level `results` array where each
result describes a single rule match. This parser extracts essential
information and converts results into the pipeline-compatible finding
dictionary format used elsewhere in the project.

The parser aims to be tolerant of slightly different Semgrep output
variants (some consumers emit lists of results directly).
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.parsers.nuclei_parser import NucleiSeverityMapper

logger = logging.getLogger(__name__)


class SemgrepSeverityMapper:
    """Map Semgrep severity values to pipeline severity levels.

    Semgrep severity strings vary ("ERROR", "WARNING", "INFO", etc.).
    This mapper normalises them to the pipeline's set: critical/high/medium/low/info.
    """

    MAP = {
        "error": "critical",
        "critical": "critical",
        "high": "high",
        "warning": "high",
        "warn": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "info",
    }

    @staticmethod
    def normalize(sev: str) -> str:
        if not sev:
            return "info"
        cleaned = str(sev).strip().lower()
        return SemgrepSeverityMapper.MAP.get(cleaned, "info")

    @staticmethod
    def score(sev: str) -> int:
        return NucleiSeverityMapper.score(SemgrepSeverityMapper.normalize(sev))


@dataclass(frozen=True)
class SemgrepFinding:
    check_id: str
    message: str
    severity: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    lines: str | None = None
    metavars: dict[str, Any] = field(default_factory=dict)


class SemgrepFindingParser:
    """Parser that converts Semgrep JSON results to pipeline findings."""

    def parse_result(self, result: dict[str, Any]) -> SemgrepFinding | None:
        if not result or not isinstance(result, dict):
            return None

        check_id = result.get("check_id") or result.get("checkId") or result.get("rule_id") or ""
        path = result.get("path") or result.get("filename") or ""

        extra = result.get("extra") or {}
        message = extra.get("message") or result.get("message") or ""
        metadata = extra.get("metadata") or {}

        severity_raw = metadata.get("severity") or result.get("severity") or "info"
        severity = SemgrepSeverityMapper.normalize(severity_raw)

        start = result.get("start") or {}
        end = result.get("end") or {}
        start_line = start.get("line") if isinstance(start, dict) else None
        end_line = end.get("line") if isinstance(end, dict) else None

        lines = extra.get("lines") or None
        metavars = extra.get("metavars") or {}

        return SemgrepFinding(
            check_id=check_id,
            message=message,
            severity=severity,
            path=path,
            start_line=start_line,
            end_line=end_line,
            metadata=metadata if isinstance(metadata, dict) else {},
            lines=lines,
            metavars=metavars if isinstance(metavars, dict) else {},
        )

    def parse_json_str(self, json_str: str) -> list[SemgrepFinding]:
        if not json_str:
            return []

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Malformed Semgrep JSON, returning empty list")
            return []

        # Semgrep may emit a single object with a `results` array, or a top-level
        # list of results. Support both shapes.
        if isinstance(data, list):
            results = data
        else:
            results = data.get("results", []) if isinstance(data, dict) else []

        findings: list[SemgrepFinding] = []
        for r in results:
            f = self.parse_result(r)
            if f is not None:
                findings.append(f)
        return findings

    def parse_file(self, filepath: str | Path) -> list[SemgrepFinding]:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Semgrep JSON file not found: {path}")
        content = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_json_str(content)

    def deduplicate(self, findings: list[SemgrepFinding]) -> list[SemgrepFinding]:
        seen: set[str] = set()
        unique: list[SemgrepFinding] = []
        for f in findings:
            key = f"{f.check_id}|{f.path}|{f.start_line}|{f.end_line}"
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if digest not in seen:
                seen.add(digest)
                unique.append(f)
        return unique

    def to_pipeline_findings(self, findings: list[SemgrepFinding]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for f in findings:
            raw = f"{f.check_id}|{f.path}|{f.start_line}|{f.end_line}"
            fid = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            evidence = {
                "check_id": f.check_id,
                "message": f.message,
                "path": f.path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "metadata": f.metadata,
                "lines": f.lines,
                "metavars": f.metavars,
            }

            out.append(
                {
                    "id": fid,
                    "module": "semgrep",
                    "category": f.check_id,
                    "severity": f.severity,
                    "score": SemgrepSeverityMapper.score(f.severity),
                    "confidence": 0.9,
                    "title": f.message or f.check_id,
                    "url": f.path,
                    "evidence": evidence,
                    "signals": sorted({"semgrep", f.check_id}),
                }
            )
        return out


def parse_semgrep_json(output: str) -> list[dict[str, Any]]:
    parser = SemgrepFindingParser()
    findings = parser.parse_json_str(output)
    findings = parser.deduplicate(findings)
    return parser.to_pipeline_findings(findings)


def parse_semgrep_json_file(filepath: str | Path) -> list[dict[str, Any]]:
    parser = SemgrepFindingParser()
    findings = parser.parse_file(filepath)
    findings = parser.deduplicate(findings)
    return parser.to_pipeline_findings(findings)
