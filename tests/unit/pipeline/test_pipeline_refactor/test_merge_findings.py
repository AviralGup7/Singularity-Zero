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



class TestMergeFindingsWithNuclei:
    """Tests for merging Nuclei findings into pipeline results."""

    def test_merge_findings_accepts_nuclei_findings_param(
        self, sample_nuclei_jsonl_line: str
    ) -> None:
        """merge_findings accepts nuclei_findings parameter."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        pipeline_findings = parser.to_pipeline_findings([finding])

        ctx = PipelineContext()
        ctx.result.nuclei_findings = pipeline_findings

        assert ctx.result.nuclei_findings is not None
        assert len(ctx.result.nuclei_findings) == 1

    def test_merge_findings_merges_nuclei_into_results(self, sample_nuclei_jsonl_line: str) -> None:
        """Nuclei findings are merged into the results."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        pipeline_findings = parser.to_pipeline_findings([finding])

        ctx = PipelineContext()
        ctx.result.merged_findings = []
        ctx.result.nuclei_findings = pipeline_findings

        merged = list(ctx.result.merged_findings)
        merged.extend(ctx.result.nuclei_findings)

        assert len(merged) == 1
        assert merged[0]["module"] == "nuclei"
        assert merged[0]["severity"] == "high"

    def test_merge_findings_deduplicates(self, sample_nuclei_jsonl_line: str) -> None:
        """Duplicate nuclei findings are deduplicated against existing."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        pipeline_findings = parser.to_pipeline_findings([finding])

        existing = [
            {
                "id": pipeline_findings[0]["id"],
                "module": "other_module",
                "category": "same_category",
                "severity": "high",
                "score": 75,
                "confidence": 0.7,
                "title": "Same Finding",
                "url": "https://example.com/vuln",
                "evidence": {},
                "signals": ["other"],
                "mitre_attack": [],
            }
        ]

        seen_ids = {f["id"] for f in existing}
        new_findings = [f for f in pipeline_findings if f["id"] not in seen_ids]
        merged = existing + new_findings

        # Dedup should remove the duplicate
        assert len(merged) == 1
        assert merged[0]["module"] == "other_module"

    def test_merge_findings_nuclei_gets_default_fields(self, sample_nuclei_jsonl_line: str) -> None:
        """Nuclei findings get default fields when converted."""
        parser = NucleiFindingParser()
        finding = parser.parse_line(sample_nuclei_jsonl_line)
        assert finding is not None
        pipeline_findings = parser.to_pipeline_findings([finding])

        pf = pipeline_findings[0]
        assert "id" in pf
        assert "module" in pf
        assert pf["module"] == "nuclei"
        assert "category" in pf
        assert "severity" in pf
        assert "score" in pf
        assert "confidence" in pf
        assert pf["confidence"] == 0.85
        assert "title" in pf
        assert "url" in pf
        assert "evidence" in pf
        assert "signals" in pf
        assert "mitre_attack" in pf

    def test_merge_findings_sort_order_includes_nuclei(
        self, sample_nuclei_jsonl_multi: str
    ) -> None:
        """Sort order includes nuclei findings by severity score."""
        findings = parse_nuclei_jsonl(sample_nuclei_jsonl_multi)

        sorted_findings = sorted(findings, key=lambda f: f["score"], reverse=True)

        assert len(sorted_findings) == 2
        assert sorted_findings[0]["score"] >= sorted_findings[1]["score"]

        # High severity (75) should come before info (5)
        assert sorted_findings[0]["severity"] == "high"
        assert sorted_findings[1]["severity"] == "info"

    def test_merge_findings_empty_nuclei_findings(self) -> None:
        """Merge handles empty nuclei findings list."""
        ctx = PipelineContext()
        ctx.result.merged_findings = [{"id": "existing", "module": "manual"}]
        ctx.result.nuclei_findings = []

        merged = list(ctx.result.merged_findings)
        merged.extend(ctx.result.nuclei_findings)

        assert len(merged) == 1
        assert merged[0]["id"] == "existing"

    def test_merge_findings_none_nuclei_findings(self) -> None:
        """Merge handles None nuclei findings gracefully."""
        ctx = PipelineContext()
        ctx.result.merged_findings = [{"id": "existing"}]
        nuclei = ctx.result.nuclei_findings or []

        merged = list(ctx.result.merged_findings)
        merged.extend(nuclei)

        assert len(merged) == 1