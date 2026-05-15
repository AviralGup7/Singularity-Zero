"""Deterministic parser for Nuclei JSONL output into pipeline Finding objects.

Nuclei outputs JSONL when run with the ``-jsonl`` flag. Each line is a JSON
object containing template metadata, matched URLs, severity classification,
and optional raw request/response data.

This module provides:
- ``NucleiFinding``: A frozen dataclass representing a single parsed finding.
- ``NucleiSeverityMapper``: Severity normalisation and scoring utilities.
- ``NucleiFindingParser``: Deterministic parser with deduplication and scope filtering.
- Convenience functions for one-shot parsing of JSONL strings and files.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline import scope_match

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

SEVERITY_SCORES: dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 5,
}

VALID_SEVERITIES = frozenset(SEVERITY_SCORES.keys())

# ---------------------------------------------------------------------------
# MITRE ATT&CK tag mapping
# ---------------------------------------------------------------------------

MITRE_TAG_MAP: dict[str, str] = {
    "cve": "N/A",
    "cwe": "N/A",
    "xss": "T1059.007",
    "sqli": "T1190",
    "sql-injection": "T1190",
    "rce": "T1190",
    "ssrf": "T1190",
    "lfi": "T1083",
    "rfi": "T1105",
    "file-read": "T1083",
    "file-upload": "T1105",
    "exposure": "T1083",
    "misconfig": "T1602",
    "misconfiguration": "T1602",
    "dns": "T1071.004",
    "subdomain-takeover": "T1583.004",
    "token-spray": "T1110",
    "brute-force": "T1110",
    "basic-auth": "T1110",
    "exposed-panel": "T1083",
    "tech-detect": "T1592",
    "waf-detect": "T1592",
    "header": "T1071",
    "cookie": "T1005",
    "oast": "T1589",
    "blind": "T1059",
    "injection": "T1059",
    "command-injection": "T1059.004",
    "template-injection": "T1059",
    "ldap": "T1190",
    "smtp": "T1071.003",
    "ftp": "T1071.001",
    "http": "T1071.001",
    "network": "T1046",
    "api": "T1071.001",
    "graphql": "T1071.001",
    "jwt": "T1550.001",
    "auth": "T1078",
    "authentication": "T1078",
    "oauth": "T1078",
    "saml": "T1078",
    "idor": "T1078",
    "race-condition": "T1499",
    "dos": "T1499",
    "ddos": "T1498",
    "crlf": "T1134",
    "ssti": "T1059",
    "xxe": "T1190",
    "deserialization": "T1059",
    "path-traversal": "T1083",
    "open-redirect": "T1036",
}


class NucleiSeverityMapper:
    """Maps Nuclei severity strings to the pipeline's SeverityLevel type.

    Nuclei uses: ``critical``, ``high``, ``medium``, ``low``, ``info``, ``unknown``.
    The pipeline uses: ``critical``, ``high``, ``medium``, ``low``, ``info``.

    ``unknown`` is normalised to ``info``.
    """

    @staticmethod
    def normalize(severity: str) -> str:
        """Normalise a raw severity string to a valid pipeline severity level.

        Args:
            severity: Raw severity string from Nuclei output.

        Returns:
            A normalised severity string guaranteed to be in ``VALID_SEVERITIES``.
        """
        cleaned = severity.strip().lower()
        if cleaned == "unknown" or cleaned not in VALID_SEVERITIES:
            return "info"
        return cleaned

    @staticmethod
    def score(severity: str) -> int:
        """Return the numeric score for a severity level.

        Args:
            severity: A normalised severity string.

        Returns:
            Integer score: critical=100, high=75, medium=50, low=25, info=5.
        """
        return SEVERITY_SCORES.get(severity.lower(), 5)


# ---------------------------------------------------------------------------
# NucleiFinding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NucleiFinding:
    """A single finding parsed from Nuclei JSONL output.

    All fields are immutable.  Lists are sorted at construction time to
    guarantee deterministic equality checks and hashing.
    """

    template_id: str
    template_name: str
    severity: str
    url: str
    host: str
    matched_at: str
    matcher_name: str
    description: str
    references: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    extracted_results: list[str] = field(default_factory=list)
    curl_command: str | None = None
    timestamp: str = ""
    finding_type: str = ""
    ip_address: str | None = None
    raw_response: str | None = None


# ---------------------------------------------------------------------------
# NucleiFindingParser
# ---------------------------------------------------------------------------


class NucleiFindingParser:
    """Deterministic parser for Nuclei JSONL output.

    Given a Nuclei JSONL string or file, this parser produces a list of
    ``NucleiFinding`` objects that can be converted to pipeline-compatible
    finding dictionaries via :meth:`to_pipeline_findings`.

    Args:
        scope_hosts: Optional set of hosts defining the assessment scope.
            When provided, :meth:`filter_in_scope` will filter findings
            to only those whose matched URL falls within scope.
    """

    def __init__(self, scope_hosts: set[str] | None = None) -> None:
        self.scope_hosts: set[str] = scope_hosts or set()

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_line(self, line: str) -> NucleiFinding | None:
        """Parse a single JSONL line into a ``NucleiFinding``.

        Args:
            line: A single line of Nuclei JSONL output.

        Returns:
            A ``NucleiFinding`` instance, or ``None`` if the line cannot be
            parsed (a warning is logged in that case).
        """
        stripped = line.strip()
        if not stripped:
            return None

        try:
            data: dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError:
            logger.warning("Malformed JSON line, skipping: %s", stripped[:120])
            return None

        if not isinstance(data, dict):
            logger.warning("JSON line is not an object, skipping: %s", stripped[:120])
            return None

        info: dict[str, Any] = data.get("info", {}) or {}
        classification: dict[str, Any] = data.get("classification", {}) or {}

        template_id: str = data.get("template-id", "")
        template_name: str = info.get("name", "")
        raw_severity: str = info.get("severity", "unknown")
        severity: str = NucleiSeverityMapper.normalize(raw_severity)

        matched_at: str = data.get("matched-at", "")
        host: str = data.get("host", "")
        ip_address: str | None = data.get("ip") or None
        finding_type: str = data.get("type", "")
        matcher_name: str = data.get("matcher-name", "")
        timestamp: str = data.get("timestamp", "")

        description: str = info.get("description", "")

        references: list[str] = self._to_sorted_list(info.get("reference", []))
        if not references:
            references = self._to_sorted_list(info.get("references", []))

        cve_ids: list[str] = self._extract_cve_ids(classification, info)
        cwe_ids: list[str] = self._extract_cwe_ids(classification, info)
        tags: list[str] = self._to_sorted_list(info.get("tags", []))
        extracted_results: list[str] = self._to_sorted_list(data.get("extracted-results", []))

        curl_command: str | None = data.get("curl-command") or None
        raw_response: str | None = data.get("response") or None

        return NucleiFinding(
            template_id=template_id,
            template_name=template_name,
            severity=severity,
            url=matched_at or host,
            host=host,
            matched_at=matched_at,
            matcher_name=matcher_name,
            description=description,
            references=references,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            tags=tags,
            extracted_results=extracted_results,
            curl_command=curl_command,
            timestamp=timestamp,
            finding_type=finding_type,
            ip_address=ip_address,
            raw_response=raw_response,
        )

    def parse_output(self, output: str) -> list[NucleiFinding]:
        """Parse complete Nuclei JSONL output string.

        Args:
            output: The full JSONL output from Nuclei (multiple lines).

        Returns:
            A list of ``NucleiFinding`` objects.  Unparseable lines are
            silently skipped (with a warning logged).
        """
        findings: list[NucleiFinding] = []
        for line in output.splitlines():
            result = self.parse_line(line)
            if result is not None:
                findings.append(result)
        return findings

    def parse_file(self, filepath: str | Path) -> list[NucleiFinding]:
        """Parse Nuclei JSONL from a file.

        Args:
            filepath: Path to the JSONL file.

        Returns:
            A list of ``NucleiFinding`` objects.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Nuclei JSONL file not found: {path}")
        content = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_output(content)

    # ------------------------------------------------------------------
    # Filtering and deduplication
    # ------------------------------------------------------------------

    def filter_in_scope(self, findings: list[NucleiFinding]) -> list[NucleiFinding]:
        """Filter findings to only include in-scope targets.

        Uses :func:`core.contracts.pipeline.scope_match` to determine whether
        each finding's ``matched_at`` URL falls within the configured scope.

        If no ``scope_hosts`` were provided at construction, all findings are
        returned unchanged.

        Args:
            findings: List of findings to filter.

        Returns:
            A new list containing only in-scope findings.
        """
        if not self.scope_hosts:
            return list(findings)

        in_scope: list[NucleiFinding] = []
        for finding in findings:
            url = finding.matched_at or finding.url
            matched, _ = scope_match(url, self.scope_hosts)
            if matched:
                in_scope.append(finding)
            else:
                logger.debug(
                    "Out-of-scope finding dropped: template=%s url=%s",
                    finding.template_id,
                    url,
                )
        return in_scope

    def deduplicate(self, findings: list[NucleiFinding]) -> list[NucleiFinding]:
        """Remove duplicate findings based on ``(template_id, url, matcher_name)``.

        Preserves the first occurrence of each unique key tuple.

        Args:
            findings: List of findings to deduplicate.

        Returns:
            A new list with duplicates removed.
        """
        seen: set[str] = set()
        unique: list[NucleiFinding] = []
        for finding in findings:
            key = f"{finding.template_id}|{finding.url}|{finding.matcher_name}"
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if digest not in seen:
                seen.add(digest)
                unique.append(finding)
        return unique

    # ------------------------------------------------------------------
    # Pipeline conversion
    # ------------------------------------------------------------------

    def to_pipeline_findings(
        self,
        nuclei_findings: list[NucleiFinding],
    ) -> list[dict[str, Any]]:
        """Convert ``NucleiFinding`` objects to pipeline-compatible finding dicts.

        Each resulting dict contains:
        - ``id``: SHA-1 digest of ``template_id + url + matcher_name``.
        - ``module``: Always ``"nuclei"``.
        - ``category``: The ``template_id``.
        - ``severity``: Normalised severity string.
        - ``score``: Numeric severity score.
        - ``confidence``: ``0.85`` (Nuclei findings are high-confidence).
        - ``title``: The template name.
        - ``url``: The matched URL.
        - ``evidence``: Dict with all Nuclei-specific metadata.
        - ``signals``: List including ``"nuclei"``, the finding type, and tags.
        - ``mitre_attack``: Extracted MITRE ATT&CK technique IDs from tags.

        Args:
            nuclei_findings: List of ``NucleiFinding`` objects.

        Returns:
            A list of pipeline-compatible finding dictionaries.
        """
        pipeline_findings: list[dict[str, Any]] = []
        for nf in nuclei_findings:
            finding_id = self._finding_id(nf)
            mitre_attack = self._extract_mitre_attack(nf.tags)
            signals = self._build_signals(nf)

            pipeline_findings.append(
                {
                    "id": finding_id,
                    "module": "nuclei",
                    "category": nf.template_id,
                    "severity": nf.severity,
                    "score": NucleiSeverityMapper.score(nf.severity),
                    "confidence": 0.85,
                    "title": nf.template_name,
                    "url": nf.matched_at or nf.url,
                    "evidence": {
                        "template_id": nf.template_id,
                        "template_name": nf.template_name,
                        "matcher_name": nf.matcher_name,
                        "description": nf.description,
                        "references": nf.references,
                        "cve_ids": nf.cve_ids,
                        "cwe_ids": nf.cwe_ids,
                        "tags": nf.tags,
                        "extracted_results": nf.extracted_results,
                        "curl_command": nf.curl_command,
                        "finding_type": nf.finding_type,
                        "host": nf.host,
                        "ip_address": nf.ip_address,
                    },
                    "signals": signals,
                    "mitre_attack": mitre_attack,
                }
            )
        return pipeline_findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_id(nf: NucleiFinding) -> str:
        """Generate a deterministic SHA-1 ID for a finding."""
        raw = f"{nf.template_id}|{nf.url}|{nf.matcher_name}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _to_sorted_list(value: Any) -> list[str]:
        """Convert a value to a sorted list of strings.

        Handles ``None``, single strings, and iterables.  Returns an empty
        list for ``None`` or empty inputs.
        """
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value else []
        if isinstance(value, (list, tuple, set)):
            return sorted({str(item) for item in value if item})
        return [str(value)]

    @staticmethod
    def _extract_cve_ids(classification: dict[str, Any], info: dict[str, Any]) -> list[str]:
        """Extract CVE IDs from the classification dict or info dict."""
        cve_ids: set[str] = set()

        classification_cves = (
            classification.get("cve-id", []) or classification.get("cve_ids", []) or []
        )
        if isinstance(classification_cves, str):
            classification_cves = [classification_cves]
        for cve in classification_cves:
            if cve:
                cve_ids.add(str(cve))

        info_cves = info.get("cve-id", []) or info.get("cve_ids", []) or []
        if isinstance(info_cves, str):
            info_cves = [info_cves]
        for cve in info_cves:
            if cve:
                cve_ids.add(str(cve))

        return sorted(cve_ids)

    @staticmethod
    def _extract_cwe_ids(classification: dict[str, Any], info: dict[str, Any]) -> list[str]:
        """Extract CWE IDs from the classification dict or info dict."""
        cwe_ids: set[str] = set()

        classification_cwes = (
            classification.get("cwe-id", []) or classification.get("cwe_ids", []) or []
        )
        if isinstance(classification_cwes, str):
            classification_cwes = [classification_cwes]
        for cwe in classification_cwes:
            if cwe:
                cwe_ids.add(str(cwe))

        info_cwes = info.get("cwe-id", []) or info.get("cwe_ids", []) or []
        if isinstance(info_cwes, str):
            info_cwes = [info_cwes]
        for cwe in info_cwes:
            if cwe:
                cwe_ids.add(str(cwe))

        return sorted(cwe_ids)

    @staticmethod
    def _extract_mitre_attack(tags: list[str]) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from tags.

        Looks for:
        - Tags that are already MITRE technique IDs (e.g. ``T1190``, ``T1059.007``).
        - Tags that match known Nuclei vulnerability categories mapped to MITRE IDs.

        Args:
            tags: Sorted list of tags from the Nuclei finding.

        Returns:
            A sorted list of unique MITRE ATT&CK technique IDs.
        """
        mitre_ids: set[str] = set()
        for tag in tags:
            tag_lower = tag.lower()

            if tag_lower.startswith("mitre") or tag_lower.startswith("attack"):
                parts = tag_lower.split(":")
                if len(parts) >= 2:
                    technique = parts[-1].upper()
                    if technique.startswith("T") and technique[1:].split(".")[0].isdigit():
                        mitre_ids.add(technique)

            if tag_lower in MITRE_TAG_MAP:
                mapped = MITRE_TAG_MAP[tag_lower]
                if mapped and mapped != "N/A":
                    mitre_ids.add(mapped)

            if tag_lower.startswith("t") and "." in tag_lower:
                technique_part = tag_lower.split(".")[0]
                if technique_part[1:].isdigit() and len(technique_part) >= 5:
                    mitre_ids.add(tag_lower.upper())
            elif tag_lower.startswith("t") and tag_lower[1:].isdigit() and len(tag_lower) >= 5:
                mitre_ids.add(tag_lower.upper())

        return sorted(mitre_ids)

    @staticmethod
    def _build_signals(nf: NucleiFinding) -> list[str]:
        """Build the signals list for a finding.

        Always includes ``"nuclei"`` and the ``finding_type``.  Appends all
        tags from the finding.

        Args:
            nf: The ``NucleiFinding`` to build signals for.

        Returns:
            A sorted list of unique signal strings.
        """
        signals: set[str] = {"nuclei"}
        if nf.finding_type:
            signals.add(nf.finding_type)
        for tag in nf.tags:
            signals.add(tag)
        return sorted(signals)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def parse_nuclei_jsonl(
    output: str,
    scope_hosts: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Parse Nuclei JSONL output into pipeline finding dicts.

    This is a convenience wrapper around :class:`NucleiFindingParser` that
    parses, deduplicates, and converts in one call.

    Args:
        output: The full Nuclei JSONL output string.
        scope_hosts: Optional set of hosts for scope filtering.

    Returns:
        A list of pipeline-compatible finding dictionaries.
    """
    parser = NucleiFindingParser(scope_hosts=scope_hosts)
    findings = parser.parse_output(output)
    findings = parser.deduplicate(findings)
    findings = parser.filter_in_scope(findings)
    return parser.to_pipeline_findings(findings)


def parse_nuclei_jsonl_file(
    filepath: str | Path,
    scope_hosts: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Parse a Nuclei JSONL file into pipeline finding dicts.

    This is a convenience wrapper around :class:`NucleiFindingParser` that
    reads a file, parses, deduplicates, and converts in one call.

    Args:
        filepath: Path to the Nuclei JSONL file.
        scope_hosts: Optional set of hosts for scope filtering.

    Returns:
        A list of pipeline-compatible finding dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    parser = NucleiFindingParser(scope_hosts=scope_hosts)
    findings = parser.parse_file(filepath)
    findings = parser.deduplicate(findings)
    findings = parser.filter_in_scope(findings)
    return parser.to_pipeline_findings(findings)
