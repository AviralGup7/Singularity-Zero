import json
import logging
import time
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from src.core.checkpoint import (
    CheckpointManager,
    CheckpointState,
    StageCheckpointGuard,
    _compute_checksum,
    _serialize_sets,
    attempt_recovery,
    create_checkpoint_manager,
    generate_run_id,
)
from src.core.middleware import (
    OutboundRequestInterceptor,
    ScopeCheckResult,
    ScopeValidator,
    ScopeViolationError,
    create_scope_guard,
    validate_url_scope,
)
from src.core.models.stage_result import (
    PipelineContext,
    StageMetric,
    StageName,
    StageResult,
    StageStatus,
)
from src.core.parsers.nuclei_parser import (
    MITRE_TAG_MAP,
    SEVERITY_SCORES,
    VALID_SEVERITIES,
    NucleiFinding,
    NucleiFindingParser,
    NucleiSeverityMapper,
    parse_nuclei_jsonl,
    parse_nuclei_jsonl_file,
)



class TestNucleiFindingParser:
    """Tests for NucleiFindingParser and related parsing utilities."""

    def test_parse_line_valid_jsonl(self, sample_nuclei_jsonl_line: str) -> None:
        """parse_line parses a valid JSONL line into NucleiFinding."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        assert finding.template_id == "cves/2023/CVE-2023-1234.yaml"
        assert finding.template_name == "Test Vulnerability"
        assert finding.severity == "high"
        assert finding.url == "https://example.com/vuln"
        assert finding.host == "https://example.com"
        assert finding.matcher_name == "body_match"

    def test_parse_line_malformed_json(self, caplog: pytest.LogCaptureFixture) -> None:
        """parse_line returns None and logs warning for malformed JSON."""
        caplog.set_level(logging.WARNING)
        parser = NucleiFindingParser()
        result = parser.parse_line("not valid json {{{")
        assert result is None
        assert any("Malformed JSON" in record.message for record in caplog.records)

    def test_parse_line_empty_line(self) -> None:
        """parse_line returns None for empty lines."""
        parser = NucleiFindingParser()
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None
        assert parser.parse_line("\n") is None

    def test_parse_line_non_dict_json(self, caplog: pytest.LogCaptureFixture) -> None:
        """parse_line returns None for JSON that is not an object."""
        caplog.set_level(logging.WARNING)
        parser = NucleiFindingParser()
        result = parser.parse_line(json.dumps([1, 2, 3]))
        assert result is None
        assert any("not an object" in record.message for record in caplog.records)

    def test_parse_output_multiple_lines(self, sample_nuclei_jsonl_multi: str) -> None:
        """parse_output processes multiple JSONL lines."""
        parser = NucleiFindingParser()
        findings = parser.parse_output(sample_nuclei_jsonl_multi)
        assert len(findings) == 2
        assert findings[0].template_id == "cves/2023/CVE-2023-1234.yaml"
        assert findings[1].template_id == "technologies/tech-detect.yaml"

    def test_parse_output_skips_malformed_lines(self) -> None:
        """parse_output skips malformed lines."""
        parser = NucleiFindingParser()
        output = json.dumps(
            {
                "template-id": "t1",
                "host": "h",
                "info": {"name": "n", "severity": "info"},
                "matcher-name": "m",
            }
        )
        output += "\nbad line\n"
        output += json.dumps(
            {
                "template-id": "t2",
                "host": "h",
                "info": {"name": "n2", "severity": "low"},
                "matcher-name": "m2",
            }
        )
        findings = parser.parse_output(output)
        assert len(findings) == 2

    def test_parse_file_existing(self, tmp_path: Path, sample_nuclei_jsonl_line: str) -> None:
        """parse_file reads and parses an existing JSONL file."""
        filepath = tmp_path / "nuclei.jsonl"
        filepath.write_text(sample_nuclei_jsonl_line)
        parser = NucleiFindingParser()
        findings = parser.parse_file(filepath)
        assert len(findings) == 1

    def test_parse_file_missing(self) -> None:
        """parse_file raises FileNotFoundError for missing files."""
        parser = NucleiFindingParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/path/file.jsonl")

    def test_severity_normalization_unknown(self) -> None:
        """Unknown severity is normalized to info."""
        assert NucleiSeverityMapper.normalize("unknown") == "info"
        assert NucleiSeverityMapper.normalize("UNKNOWN") == "info"

    def test_severity_normalization_invalid(self) -> None:
        """Invalid severity is normalized to info."""
        assert NucleiSeverityMapper.normalize("bogus") == "info"
        assert NucleiSeverityMapper.normalize("") == "info"

    def test_severity_normalization_valid(self) -> None:
        """Valid severities are preserved."""
        for sev in VALID_SEVERITIES:
            assert NucleiSeverityMapper.normalize(sev) == sev

    def test_severity_scoring(self) -> None:
        """Severity scores match expected values."""
        assert NucleiSeverityMapper.score("critical") == 100
        assert NucleiSeverityMapper.score("high") == 75
        assert NucleiSeverityMapper.score("medium") == 50
        assert NucleiSeverityMapper.score("low") == 25
        assert NucleiSeverityMapper.score("info") == 5

    def test_cve_id_extraction_from_classification(self, sample_nuclei_jsonl_line: str) -> None:
        """CVE IDs are extracted from classification dict."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        assert "CVE-2023-1234" in finding.cve_ids

    def test_cwe_id_extraction(self, sample_nuclei_jsonl_line: str) -> None:
        """CWE IDs are extracted from classification dict."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        assert "CWE-79" in finding.cwe_ids

    def test_mitre_attack_extraction_from_tags(self, sample_nuclei_jsonl_line: str) -> None:
        """MITRE ATT&CK techniques are extracted from tags."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        # "xss" tag maps to T1059.007
        pipeline_findings = parser.to_pipeline_findings([finding])
        assert len(pipeline_findings) == 1
        assert "T1059.007" in pipeline_findings[0]["mitre_attack"]

    def test_mitre_attack_extraction_cve_tag(self) -> None:
        """CVE tag does not produce MITRE ID (maps to N/A)."""
        mitre_ids = NucleiFindingParser._extract_mitre_attack(["cve"])
        assert "N/A" not in mitre_ids

    def test_deduplication_by_key(self, sample_nuclei_jsonl_line: str) -> None:
        """Deduplication removes duplicates by (template_id, url, matcher_name)."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        findings = [finding, finding, finding]
        unique = parser.deduplicate(findings)
        assert len(unique) == 1

    def test_deduplication_preserves_distinct(self) -> None:
        """Deduplication preserves distinct findings."""
        parser = NucleiFindingParser()
        f1 = NucleiFinding(
            template_id="t1",
            template_name="n1",
            severity="high",
            url="https://example.com/1",
            host="https://example.com",
            matched_at="https://example.com/1",
            matcher_name="m1",
            description="d1",
        )
        f2 = NucleiFinding(
            template_id="t2",
            template_name="n2",
            severity="low",
            url="https://example.com/2",
            host="https://example.com",
            matched_at="https://example.com/2",
            matcher_name="m2",
            description="d2",
        )
        unique = parser.deduplicate([f1, f2, f1, f2])
        assert len(unique) == 2

    def test_filter_in_scope_with_scope_hosts(self) -> None:
        """filter_in_scope filters findings based on scope_hosts."""
        parser = NucleiFindingParser(scope_hosts={"example.com"})
        f1 = NucleiFinding(
            template_id="t1",
            template_name="n1",
            severity="high",
            url="https://example.com/vuln",
            host="https://example.com",
            matched_at="https://example.com/vuln",
            matcher_name="m1",
            description="d1",
        )
        f2 = NucleiFinding(
            template_id="t2",
            template_name="n2",
            severity="low",
            url="https://evil.com/vuln",
            host="https://evil.com",
            matched_at="https://evil.com/vuln",
            matcher_name="m2",
            description="d2",
        )
        filtered = parser.filter_in_scope([f1, f2])
        assert len(filtered) == 1
        assert filtered[0].template_id == "t1"

    def test_filter_in_scope_no_scope_hosts_returns_all(self) -> None:
        """filter_in_scope returns all findings when no scope_hosts set."""
        parser = NucleiFindingParser()
        f1 = NucleiFinding(
            template_id="t1",
            template_name="n1",
            severity="high",
            url="https://example.com/vuln",
            host="https://example.com",
            matched_at="https://example.com/vuln",
            matcher_name="m1",
            description="d1",
        )
        f2 = NucleiFinding(
            template_id="t2",
            template_name="n2",
            severity="low",
            url="https://evil.com/vuln",
            host="https://evil.com",
            matched_at="https://evil.com/vuln",
            matcher_name="m2",
            description="d2",
        )
        filtered = parser.filter_in_scope([f1, f2])
        assert len(filtered) == 2

    def test_to_pipeline_findings_structure(self, sample_nuclei_jsonl_line: str) -> None:
        """to_pipeline_findings produces correct dict structure."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        pipeline_findings = parser.to_pipeline_findings([finding])
        assert len(pipeline_findings) == 1
        pf = pipeline_findings[0]
        assert pf["module"] == "nuclei"
        assert pf["category"] == "cves/2023/CVE-2023-1234.yaml"
        assert pf["severity"] == "high"
        assert pf["score"] == 75
        assert pf["confidence"] == 0.85
        assert pf["title"] == "Test Vulnerability"
        assert "id" in pf
        assert "evidence" in pf
        assert "signals" in pf
        assert "mitre_attack" in pf

    def test_to_pipeline_findings_evidence_fields(self, sample_nuclei_jsonl_line: str) -> None:
        """Pipeline finding evidence contains expected sub-fields."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        pipeline_findings = parser.to_pipeline_findings([finding])
        evidence = pipeline_findings[0]["evidence"]
        assert "template_id" in evidence
        assert "cve_ids" in evidence
        assert "cwe_ids" in evidence
        assert "tags" in evidence
        assert "references" in evidence

    def test_deterministic_output(self, sample_nuclei_jsonl_multi: str) -> None:
        """Same input always produces the same output."""
        parser = NucleiFindingParser()
        findings1 = parser.parse_output(sample_nuclei_jsonl_multi)
        findings2 = parser.parse_output(sample_nuclei_jsonl_multi)
        assert findings1 == findings2

    def test_sorted_lists_in_output(self, sample_nuclei_jsonl_line: str) -> None:
        """CVE IDs, tags, and references are sorted in output."""
        data = json.loads(sample_nuclei_jsonl_line)
        data["info"]["tags"] = ["zebra", "alpha", "xss"]
        data["classification"]["cve-id"] = ["CVE-2023-9999", "CVE-2023-0001"]
        line = json.dumps(data)

        parser = NucleiFindingParser()
        finding = parser.parse_line(line)
        assert finding is not None
        assert finding.tags == sorted(finding.tags)
        assert finding.cve_ids == sorted(finding.cve_ids)

    def test_parse_nuclei_jsonl_convenience(self, sample_nuclei_jsonl_multi: str) -> None:
        """parse_nuclei_jsonl is a convenience function."""
        findings = parse_nuclei_jsonl(sample_nuclei_jsonl_multi)
        assert isinstance(findings, list)
        assert len(findings) == 2
        assert findings[0]["module"] == "nuclei"

    def test_parse_nuclei_jsonl_file_convenience(
        self, tmp_path: Path, sample_nuclei_jsonl_multi: str
    ) -> None:
        """parse_nuclei_jsonl_file reads and parses a file."""
        filepath = tmp_path / "nuclei.jsonl"
        filepath.write_text(sample_nuclei_jsonl_multi)
        findings = parse_nuclei_jsonl_file(filepath)
        assert len(findings) == 2

    def test_parse_nuclei_jsonl_file_missing(self) -> None:
        """parse_nuclei_jsonl_file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            parse_nuclei_jsonl_file("/nonexistent/nuclei.jsonl")

    def test_severity_score_mapping_completeness(self) -> None:
        """All valid severities have scores defined."""
        for sev in VALID_SEVERITIES:
            assert sev in SEVERITY_SCORES
            assert SEVERITY_SCORES[sev] > 0

    def test_mitre_tag_map_completeness(self) -> None:
        """MITRE_TAG_MAP contains expected entries."""
        assert "xss" in MITRE_TAG_MAP
        assert "sqli" in MITRE_TAG_MAP
        assert "rce" in MITRE_TAG_MAP

    def test_finding_id_is_deterministic(self) -> None:
        """Finding ID is deterministic for same input."""
        f1 = NucleiFinding(
            template_id="t1",
            template_name="n1",
            severity="high",
            url="https://example.com/vuln",
            host="https://example.com",
            matched_at="https://example.com/vuln",
            matcher_name="m1",
            description="d1",
        )
        f2 = NucleiFinding(
            template_id="t1",
            template_name="n1",
            severity="high",
            url="https://example.com/vuln",
            host="https://example.com",
            matched_at="https://example.com/vuln",
            matcher_name="m1",
            description="d1",
        )
        parser = NucleiFindingParser()
        id1 = parser._finding_id(f1)
        id2 = parser._finding_id(f2)
        assert id1 == id2

    def test_to_sorted_list_handles_various_inputs(self) -> None:
        """_to_sorted_list handles None, strings, lists, and single values."""
        assert NucleiFindingParser._to_sorted_list(None) == []
        assert NucleiFindingParser._to_sorted_list("") == []
        assert NucleiFindingParser._to_sorted_list("single") == ["single"]
        assert NucleiFindingParser._to_sorted_list(["b", "a"]) == ["a", "b"]
        assert NucleiFindingParser._to_sorted_list(42) == ["42"]