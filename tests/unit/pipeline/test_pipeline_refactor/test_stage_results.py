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



class TestStageResult:
    """Tests for StageResult dataclass and serialization."""

    def test_default_construction(self) -> None:
        """StageResult can be constructed with no arguments."""
        result = StageResult()
        assert isinstance(result.subdomains, set)
        assert isinstance(result.urls, set)
        assert isinstance(result.live_hosts, set)
        assert isinstance(result.parameters, set)
        assert isinstance(result.scope_entries, list)
        assert isinstance(result.module_metrics, dict)
        assert isinstance(result.stage_status, dict)
        assert result.use_cache is False
        assert result.discovery_enabled is True
        assert result.started_at > 0

    def test_field_assignment(self) -> None:
        """Fields can be assigned after construction."""
        result = StageResult()
        result.subdomains.add("api.example.com")
        result.urls.add("https://example.com/api")
        result.use_cache = True
        assert "api.example.com" in result.subdomains
        assert result.use_cache is True

    def test_to_dict_json_serializable(self) -> None:
        """to_dict produces a JSON-serializable dictionary."""
        result = StageResult()
        result.subdomains.add("b.com")
        result.subdomains.add("a.com")
        result.previous_run = Path("/tmp/prev")
        data = result.to_dict()
        # Should not raise
        json.dumps(data)
        assert isinstance(data["subdomains"], list)
        assert data["subdomains"] == ["a.com", "b.com"]
        assert isinstance(data["previous_run"], str)
        assert "prev" in data["previous_run"]

    def test_from_dict_restores_sets(self) -> None:
        """from_dict converts lists back to sets for set fields."""
        data = {
            "subdomains": ["api.example.com", "www.example.com"],
            "live_hosts": ["https://api.example.com"],
            "urls": ["https://example.com"],
            "parameters": ["id", "name"],
        }
        result = StageResult.from_dict(data)
        assert result.subdomains == {"api.example.com", "www.example.com"}
        assert result.live_hosts == {"https://api.example.com"}
        assert result.urls == {"https://example.com"}
        assert result.parameters == {"id", "name"}

    def test_from_dict_handles_missing_fields(self) -> None:
        """from_dict uses defaults for missing fields."""
        result = StageResult.from_dict({})
        assert isinstance(result.subdomains, set)
        assert isinstance(result.urls, set)
        assert result.use_cache is False

    def test_to_json_roundtrip(self) -> None:
        """to_json / from_json roundtrip preserves data."""
        result = StageResult()
        result.subdomains.add("test.example.com")
        result.use_cache = True
        result.discovery_enabled = False

        json_str = result.to_json()
        restored = StageResult.from_json(json_str)

        assert restored.subdomains == {"test.example.com"}
        assert restored.use_cache is True
        assert restored.discovery_enabled is False

    def test_snapshot_restore_roundtrip(self) -> None:
        """snapshot / restore roundtrip preserves data."""
        result = StageResult()
        result.subdomains.add("snap.example.com")
        result.urls.add("https://snap.example.com/page")

        snap = result.snapshot()
        restored = StageResult.restore(snap)

        assert restored.subdomains == {"snap.example.com"}
        assert restored.urls == {"https://snap.example.com/page"}

    def test_sets_are_sorted_in_serialization(self) -> None:
        """Sets are converted to sorted lists in to_dict."""
        result = StageResult()
        result.subdomains = {"z.com", "a.com", "m.com"}
        data = result.to_dict()
        assert data["subdomains"] == ["a.com", "m.com", "z.com"]

    def test_path_objects_converted_to_strings(self) -> None:
        """Path objects are converted to strings in serialization."""
        result = StageResult()
        result.previous_run = Path("some/path")
        data = result.to_dict()
        assert isinstance(data["previous_run"], str)
        assert "path" in data["previous_run"]
        assert "path" in data["previous_run"]

    def test_from_dict_restores_path(self) -> None:
        """from_dict converts string paths back to Path objects."""
        data = {"previous_run": "/some/path"}
        result = StageResult.from_dict(data)
        assert result.previous_run == Path("/some/path")
        assert isinstance(result.previous_run, Path)

    def test_pipeline_context_construction(self) -> None:
        """PipelineContext can be constructed with defaults."""
        ctx = PipelineContext()
        assert isinstance(ctx.result, StageResult)
        assert ctx.output_store is None

    def test_pipeline_context_mark_stage_complete(self) -> None:
        """mark_stage_complete sets status and optional metrics."""
        ctx = PipelineContext()
        metrics: StageMetric = {"duration_seconds": 5.0}
        ctx.mark_stage_complete("scope", metrics)
        assert ctx.result.stage_status["scope"] == StageStatus.COMPLETED.value
        assert ctx.result.module_metrics["scope"]["duration_seconds"] == 5.0

    def test_pipeline_context_mark_stage_failed(self) -> None:
        """mark_stage_failed sets status and records error."""
        ctx = PipelineContext()
        ctx.mark_stage_failed("nuclei_scan", "Tool not found")
        assert ctx.result.stage_status["nuclei_scan"] == StageStatus.FAILED.value
        assert ctx.result.module_metrics["nuclei_scan"]["error"] == "Tool not found"
        assert "finished_at" in ctx.result.module_metrics["nuclei_scan"]

    def test_pipeline_context_mark_stage_skipped(self) -> None:
        """mark_stage_skipped sets status and records reason."""
        ctx = PipelineContext()
        ctx.mark_stage_skipped("screenshots", "No live hosts")
        assert ctx.result.stage_status["screenshots"] == StageStatus.SKIPPED.value
        assert ctx.result.module_metrics["screenshots"]["reason"] == "No live hosts"

    def test_pipeline_context_property_accessors_delegate(self) -> None:
        """Property accessors on PipelineContext delegate to StageResult."""
        ctx = PipelineContext()
        ctx.subdomains.add("delegated.example.com")
        assert "delegated.example.com" in ctx.subdomains

        ctx.scope_entries = ["entry1"]
        assert ctx.scope_entries == ["entry1"]

        ctx.use_cache = True
        assert ctx.use_cache is True

        ctx.discovery_enabled = False
        assert ctx.discovery_enabled is False

    def test_pipeline_context_serialization_excludes_output_store(self) -> None:
        """to_dict sets output_store to None for serialization."""
        ctx = PipelineContext()
        ctx.output_store = MagicMock()
        data = ctx.to_dict()
        assert data["output_store"] is None
        json.dumps(data)

    def test_pipeline_context_from_dict(self) -> None:
        """from_dict restores PipelineContext from dict."""
        ctx = PipelineContext()
        ctx.subdomains.add("restore.example.com")
        data = ctx.to_dict()
        restored = PipelineContext.from_dict(data)
        assert restored.subdomains == {"restore.example.com"}

    def test_pipeline_context_json_roundtrip(self) -> None:
        """to_json / from_json roundtrip for PipelineContext."""
        ctx = PipelineContext()
        ctx.urls.add("https://roundtrip.example.com")
        json_str = ctx.to_json()
        restored = PipelineContext.from_json(json_str)
        assert restored.urls == {"https://roundtrip.example.com"}

    def test_stage_status_enum_values(self) -> None:
        """StageStatus enum has expected values."""
        assert StageStatus.PENDING.value == "PENDING"
        assert StageStatus.RUNNING.value == "RUNNING"
        assert StageStatus.COMPLETED.value == "COMPLETED"
        assert StageStatus.FAILED.value == "FAILED"
        assert StageStatus.SKIPPED.value == "SKIPPED"

    def test_stage_name_enum_values(self) -> None:
        """StageName enum has expected values."""
        assert StageName.SCOPE.value == "scope"
        assert StageName.NUCLEI_SCAN.value == "nuclei_scan"
        assert StageName.REPORTING.value == "reporting"

    def test_to_dict_includes_all_fields(self) -> None:
        """to_dict includes every dataclass field."""
        result = StageResult()
        data = result.to_dict()
        field_names = {f.name for f in result.__dataclass_fields__.values()}
        assert field_names == set(data.keys())

    def test_snapshot_is_alias_for_to_dict(self) -> None:
        """snapshot returns the same data as to_dict."""
        result = StageResult()
        result.subdomains.add("alias.example.com")
        assert result.snapshot() == result.to_dict()

    def test_restore_is_alias_for_from_dict(self) -> None:
        """restore returns the same result as from_dict."""
        data = {"subdomains": ["restore-alias.example.com"]}
        assert StageResult.restore(data).subdomains == StageResult.from_dict(data).subdomains