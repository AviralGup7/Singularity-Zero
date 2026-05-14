"""Comprehensive test suite for pipeline refactored components.

Tests cover:
- StageResult, PipelineContext, StageStatus
- ScopeValidator, ScopeCheckResult, ScopeViolationError, OutboundRequestInterceptor
- NucleiFindingParser, NucleiSeverityMapper, NucleiFinding
- CheckpointManager, CheckpointState, StageCheckpointGuard
- merge_findings integration
"""

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

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_nuclei_jsonl_line() -> str:
    """Return a single valid Nuclei JSONL line."""
    return json.dumps(
        {
            "template-id": "cves/2023/CVE-2023-1234.yaml",
            "matched-at": "https://example.com/vuln",
            "host": "https://example.com",
            "info": {
                "name": "Test Vulnerability",
                "severity": "high",
                "description": "A test vulnerability",
                "reference": ["https://example.com/ref"],
                "tags": ["cve", "xss"],
            },
            "classification": {
                "cve-id": ["CVE-2023-1234"],
                "cwe-id": ["CWE-79"],
            },
            "matcher-name": "body_match",
            "type": "http",
            "timestamp": "2024-01-01T00:00:00Z",
            "curl-command": "curl https://example.com/vuln",
            "ip": "93.184.216.34",
        }
    )


@pytest.fixture
def sample_nuclei_jsonl_multi(sample_nuclei_jsonl_line: str) -> str:
    """Return multiple Nuclei JSONL lines."""
    line2 = json.dumps(
        {
            "template-id": "technologies/tech-detect.yaml",
            "matched-at": "https://example.com/",
            "host": "https://example.com",
            "info": {
                "name": "Technology Detection",
                "severity": "info",
                "description": "Detected technology",
                "tags": ["tech-detect"],
            },
            "matcher-name": "header_match",
            "type": "http",
            "timestamp": "2024-01-01T00:00:01Z",
        }
    )
    return f"{sample_nuclei_jsonl_line}\n{line2}"


@pytest.fixture
def scope_validator() -> ScopeValidator:
    """Return a ScopeValidator with common test scope hosts."""
    return ScopeValidator(
        {
            "example.com",
            "*.api.example.com",
            "192.168.1.0/24",
            "10.0.0.1",
        }
    )


@pytest.fixture
def checkpoint_manager(tmp_path: Path) -> CheckpointManager:
    """Return a CheckpointManager backed by a temp directory."""
    return CheckpointManager(tmp_path / "checkpoints", "test-run-001")


@pytest.fixture
def checkpoint_state() -> CheckpointState:
    """Return a CheckpointState with test data."""
    return CheckpointState(
        pipeline_run_id="test-run-001",
        checkpoint_version=1,
        completed_stages=["scope", "subdomain_discovery"],
        current_stage="host_probing",
        stage_results={"scope": {"status": "completed"}},
        module_metrics={"scope_duration": 1.5},
    )


# ===========================================================================
# 1. TestStageResult
# ===========================================================================


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


# ===========================================================================
# 2. TestScopeValidator
# ===========================================================================


class TestScopeValidator:
    """Tests for ScopeValidator and related middleware components."""

    def test_exact_hostname_match(self, scope_validator: ScopeValidator) -> None:
        """Exact hostname match is allowed."""
        result = scope_validator.check("https://example.com/page")
        assert result.allowed is True
        assert "Exact match" in result.reason

    def test_wildcard_subdomain_match(self, scope_validator: ScopeValidator) -> None:
        """Wildcard subdomain *.api.example.com matches api.example.com."""
        result = scope_validator.check("https://api.example.com/v1")
        assert result.allowed is True
        assert "Wildcard match" in result.reason

    def test_wildcard_subdomain_match_nested(self, scope_validator: ScopeValidator) -> None:
        """Wildcard subdomain *.api.example.com matches v2.api.example.com."""
        result = scope_validator.check("https://v2.api.example.com/v1")
        assert result.allowed is True

    def test_implicit_subdomain_match(self, scope_validator: ScopeValidator) -> None:
        """example.com implicitly matches www.example.com."""
        result = scope_validator.check("https://www.example.com/page")
        assert result.allowed is True
        assert "Implicit subdomain" in result.reason

    def test_sensitive_subdomain_is_excluded_unless_explicitly_scoped(self) -> None:
        """Sensitive host labels are not admitted by broad wildcard or parent scope."""
        validator = ScopeValidator({"example.com", "*.example.com"})
        result = validator.check("https://vault.example.com/secrets")
        assert result.allowed is False
        assert "Sensitive internal hostname" in result.reason

        explicit = ScopeValidator({"example.com", "vault.example.com"})
        assert explicit.check("https://vault.example.com/secrets").allowed is True

    def test_ip_exact_match(self, scope_validator: ScopeValidator) -> None:
        """Exact IP address match is allowed."""
        result = scope_validator.check("http://10.0.0.1/admin")
        assert result.allowed is True
        assert "Exact match" in result.reason

    def test_cidr_range_match(self, scope_validator: ScopeValidator) -> None:
        """CIDR range 192.168.1.0/24 matches 192.168.1.50."""
        result = scope_validator.check("http://192.168.1.50/api")
        assert result.allowed is True
        assert "CIDR range" in result.reason

    def test_out_of_scope_rejection(self, scope_validator: ScopeValidator) -> None:
        """Out-of-scope host is rejected."""
        result = scope_validator.check("https://evil.com/page")
        assert result.allowed is False
        assert result.matched_rule is None
        assert "not within the defined scope" in result.reason

    def test_url_with_path_and_query(self, scope_validator: ScopeValidator) -> None:
        """URL with path and query params is validated by hostname."""
        result = scope_validator.check("https://example.com/search?q=test&page=1&limit=10")
        assert result.allowed is True

    def test_case_insensitive_matching(self, scope_validator: ScopeValidator) -> None:
        """Hostname matching is case-insensitive."""
        result = scope_validator.check("https://EXAMPLE.COM/page")
        assert result.allowed is True

    def test_add_scope_dynamically(self, scope_validator: ScopeValidator) -> None:
        """add_scope adds a new host to the validator."""
        # Use a host not implicitly matched by example.com
        assert not scope_validator.check_hostname("totally-different.com").allowed
        scope_validator.add_scope("totally-different.com")
        result = scope_validator.check_hostname("totally-different.com")
        assert result.allowed is True

    def test_remove_scope_dynamically(self, scope_validator: ScopeValidator) -> None:
        """remove_scope removes a host from the validator."""
        assert scope_validator.check_hostname("example.com").allowed
        scope_validator.remove_scope("example.com")
        # After removal, implicit subdomain match is gone
        result = scope_validator.check_hostname("example.com")
        assert result.allowed is False

    def test_get_scope_rules(self, scope_validator: ScopeValidator) -> None:
        """get_scope_rules returns rules added via add_scope."""
        # Initial hosts added in __init__ are not in _rules list
        # Only hosts added via add_scope appear in get_scope_rules
        scope_validator.add_scope("dynamic.example.com")
        rules = scope_validator.get_scope_rules()
        assert isinstance(rules, list)
        assert "dynamic.example.com" in rules

    def test_check_hostname_standalone(self, scope_validator: ScopeValidator) -> None:
        """check_hostname validates hostnames without full URLs."""
        result = scope_validator.check_hostname("example.com")
        assert result.allowed is True
        assert result.hostname == "example.com"

    def test_check_hostname_out_of_scope(self, scope_validator: ScopeValidator) -> None:
        """check_hostname rejects out-of-scope hostnames."""
        result = scope_validator.check_hostname("evil.com")
        assert result.allowed is False

    def test_check_ip_standalone(self, scope_validator: ScopeValidator) -> None:
        """check_ip validates IP addresses."""
        result = scope_validator.check_ip("192.168.1.100")
        assert result.allowed is True
        assert result.ip_address == "192.168.1.100"

    def test_check_ip_out_of_scope(self, scope_validator: ScopeValidator) -> None:
        """check_ip rejects out-of-scope IPs."""
        result = scope_validator.check_ip("172.16.0.1")
        assert result.allowed is False

    def test_check_ip_invalid(self, scope_validator: ScopeValidator) -> None:
        """check_ip handles invalid IP addresses."""
        result = scope_validator.check_ip("not-an-ip")
        assert result.allowed is False
        assert "Invalid IP address" in result.reason

    def test_invalid_url_handling(self, scope_validator: ScopeValidator) -> None:
        """Invalid URLs are rejected gracefully."""
        result = scope_validator.check("not-a-valid-url")
        assert result.allowed is False

    def test_empty_scope_hosts_behavior(self) -> None:
        """Validator with empty scope rejects everything."""
        validator = ScopeValidator(set())
        result = validator.check("https://example.com")
        assert result.allowed is False

    def test_scope_check_result_dataclass_fields(self) -> None:
        """ScopeCheckResult has all expected fields."""
        result = ScopeCheckResult(
            allowed=True,
            reason="test",
            matched_rule="example.com",
            url="https://example.com",
            hostname="example.com",
            ip_address="1.2.3.4",
        )
        assert result.allowed is True
        assert result.reason == "test"
        assert result.matched_rule == "example.com"
        assert result.url == "https://example.com"
        assert result.hostname == "example.com"
        assert result.ip_address == "1.2.3.4"

    def test_scope_violation_error_attributes(self) -> None:
        """ScopeViolationError has correct attributes and message."""
        error = ScopeViolationError(
            target_url="https://evil.com",
            reason="Out of scope",
            scope_hosts={"example.com"},
        )
        assert error.target_url == "https://evil.com"
        assert error.reason == "Out of scope"
        assert error.scope_hosts == frozenset({"example.com"})
        assert "Scope violation" in str(error)
        assert "https://evil.com" in str(error)

    def test_validate_url_scope_convenience(self) -> None:
        """validate_url_scope is a convenience function."""
        result = validate_url_scope(
            "https://api.example.com/v1",
            {"example.com", "*.example.com"},
        )
        assert result.allowed is True

    def test_validate_url_scope_out_of_scope(self) -> None:
        """validate_url_scope rejects out-of-scope URLs."""
        result = validate_url_scope(
            "https://evil.com",
            {"example.com"},
        )
        assert result.allowed is False

    def test_create_scope_guard_decorator_factory(self) -> None:
        """create_scope_guard returns a decorator that guards functions."""
        guard = create_scope_guard({"example.com"})

        @guard
        def safe_request(method: str, url: str, **kwargs: str) -> tuple[str, str]:
            return method, url

        method, url = safe_request("GET", "https://example.com/api")
        assert method == "GET"
        assert url == "https://example.com/api"

    def test_create_scope_guard_blocks_out_of_scope(self) -> None:
        """create_scope_guard decorator raises for out-of-scope URLs."""
        guard = create_scope_guard({"example.com"})

        @guard
        def safe_request(method: str, url: str, **kwargs: str) -> tuple[str, str]:
            return method, url

        with pytest.raises(ScopeViolationError):
            safe_request("GET", "https://evil.com")

    def test_outbound_request_interceptor_allowed(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor.intercept returns method/url for allowed."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        method, url = interceptor.intercept("GET", "https://example.com/api")
        assert method == "GET"
        assert url == "https://example.com/api"

    def test_outbound_request_interceptor_blocked(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor.intercept raises for blocked URLs."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        with pytest.raises(ScopeViolationError):
            interceptor.intercept("POST", "https://evil.com/hack")

    def test_outbound_request_interceptor_audit_log(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor maintains an audit log."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        interceptor.intercept("GET", "https://example.com")
        try:
            interceptor.intercept("GET", "https://evil.com")
        except ScopeViolationError:
            pass

        log = interceptor.audit_log
        assert len(log) == 2
        assert log[0]["allowed"] is True
        assert log[1]["allowed"] is False
        assert "timestamp" in log[0]
        assert "method" in log[0]
        assert "url" in log[0]

    def test_outbound_request_interceptor_counts(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor tracks blocked/allowed counts."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        interceptor.intercept("GET", "https://example.com/1")
        interceptor.intercept("GET", "https://example.com/2")
        try:
            interceptor.intercept("GET", "https://evil.com")
        except ScopeViolationError:
            pass

        assert interceptor.allowed_count == 2
        assert interceptor.blocked_count == 1

    def test_outbound_request_interceptor_callable(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor is callable."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        method, url = interceptor("GET", "https://example.com")
        assert method == "GET"

    def test_outbound_request_interceptor_audit_log_is_copy(
        self, scope_validator: ScopeValidator
    ) -> None:
        """audit_log returns a copy, not the internal list."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        interceptor.intercept("GET", "https://example.com")
        log1 = interceptor.audit_log
        log2 = interceptor.audit_log
        assert log1 is not log2


# ===========================================================================
# 3. TestNucleiFindingParser
# ===========================================================================


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


# ===========================================================================
# 4. TestCheckpointManager
# ===========================================================================


class TestCheckpointManager:
    """Tests for CheckpointManager and checkpointing utilities."""

    def test_save_and_load_roundtrip(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """Saved checkpoint can be loaded back."""
        path = checkpoint_manager.save(checkpoint_state)
        assert path.exists()

        loaded = checkpoint_manager.load()
        assert loaded is not None
        assert loaded.pipeline_run_id == "test-run-001"
        assert set(loaded.completed_stages) == {"scope", "subdomain_discovery"}
        assert loaded.current_stage == "host_probing"

    def test_atomic_write_uses_temp_file(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """Save uses temp file + rename pattern."""
        path = checkpoint_manager.save(checkpoint_state)
        # Temp file should not exist after successful save
        tmp_path = path.with_suffix(".tmp")
        assert not tmp_path.exists()
        assert path.exists()

    def test_checksum_integrity_verification(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """Checkpoint checksum verifies integrity."""
        checkpoint_manager.save(checkpoint_state)
        loaded = checkpoint_manager.load()
        assert loaded is not None
        # If checksum failed, load would return None
        assert loaded.pipeline_run_id == checkpoint_state.pipeline_run_id

    def test_checksum_detects_corruption(
        self,
        checkpoint_manager: CheckpointManager,
        checkpoint_state: CheckpointState,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Corrupted checkpoint is detected and load returns None."""
        caplog.set_level(logging.WARNING)
        path = checkpoint_manager.save(checkpoint_state)
        # Corrupt the file
        content = path.read_text()
        content = content.replace('"completed_stages"', '"completed_stages_CORRUPTED"')
        path.write_text(content)

        loaded = checkpoint_manager.load()
        assert loaded is None
        assert any("integrity check failed" in record.message.lower() for record in caplog.records)

    def test_mark_stage_complete(self, checkpoint_manager: CheckpointManager) -> None:
        """mark_stage_complete updates state and persists."""
        checkpoint_manager.mark_stage_complete("scope", {"status": "ok"})
        state = checkpoint_manager.load()
        assert state is not None
        assert "scope" in state.completed_stages
        assert state.stage_results["scope"]["status"] == "ok"
        assert state.current_stage is None

    def test_mark_stage_failed(self, checkpoint_manager: CheckpointManager) -> None:
        """mark_stage_failed records failure details."""
        checkpoint_manager.mark_stage_failed("nuclei_scan", "Tool crashed")
        state = checkpoint_manager.load()
        assert state is not None
        assert state.stage_results["nuclei_scan"]["status"] == "failed"
        assert state.stage_results["nuclei_scan"]["error"] == "Tool crashed"

    def test_should_resume_no_checkpoint(self, tmp_path: Path) -> None:
        """should_resume returns False when no checkpoint exists."""
        manager = CheckpointManager(tmp_path / "cp", "new-run")
        can_resume, state = manager.should_resume()
        assert can_resume is False
        assert state is None

    def test_should_resume_with_checkpoint(self, checkpoint_manager: CheckpointManager) -> None:
        """should_resume returns True when checkpoint exists."""
        checkpoint_manager.mark_stage_complete("scope", {})
        can_resume, state = checkpoint_manager.should_resume()
        assert can_resume is True
        assert state is not None

    def test_get_remaining_stages(self, checkpoint_manager: CheckpointManager) -> None:
        """get_remaining_stages returns uncompleted stages."""
        checkpoint_manager.mark_stage_complete("scope", {})
        checkpoint_manager.mark_stage_complete("subdomain_discovery", {})
        all_stages = ["scope", "subdomain_discovery", "host_probing", "nuclei_scan"]
        remaining = checkpoint_manager.get_remaining_stages(all_stages)
        assert remaining == ["host_probing", "nuclei_scan"]

    def test_cleanup_old_checkpoints(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """cleanup_old_checkpoints removes excess files."""
        for i in range(5):
            state = CheckpointState(
                pipeline_run_id="test-run-001",
                checkpoint_version=i + 1,
                completed_stages=[f"stage_{i}"],
            )
            checkpoint_manager.save(state)

        deleted = checkpoint_manager.cleanup_old_checkpoints(keep_last=2)
        assert deleted == 3

        files = list(checkpoint_manager._run_dir.glob("checkpoint_v*.json"))
        assert len(files) == 2

    def test_cleanup_no_op_when_under_limit(
        self, checkpoint_manager: CheckpointManager, checkpoint_state: CheckpointState
    ) -> None:
        """cleanup_old_checkpoints does nothing when under limit."""
        checkpoint_manager.save(checkpoint_state)
        deleted = checkpoint_manager.cleanup_old_checkpoints(keep_last=5)
        assert deleted == 0

    def test_get_checkpoint_history(self, checkpoint_manager: CheckpointManager) -> None:
        """get_checkpoint_history returns metadata for all checkpoints."""
        checkpoint_manager.mark_stage_complete("scope", {})
        checkpoint_manager.mark_stage_complete("subdomain_discovery", {})
        history = checkpoint_manager.get_checkpoint_history()
        assert len(history) == 2
        assert history[0]["version"] == 1
        assert history[1]["version"] == 2
        assert "timestamp" in history[0]
        assert "file" in history[0]

    def test_get_checkpoint_history_empty(self, tmp_path: Path) -> None:
        """get_checkpoint_history returns empty list when no checkpoints."""
        manager = CheckpointManager(tmp_path / "cp", "empty-run")
        assert manager.get_checkpoint_history() == []

    def test_stage_checkpoint_guard_success(self, checkpoint_manager: CheckpointManager) -> None:
        """StageCheckpointGuard marks stage complete on normal exit."""
        with StageCheckpointGuard(checkpoint_manager, "test_stage"):
            pass

        state = checkpoint_manager.load()
        assert state is not None
        assert state.stage_results["test_stage"]["status"] == "completed"
        assert "elapsed_seconds" in state.stage_results["test_stage"]

    def test_stage_checkpoint_guard_failure(self, checkpoint_manager: CheckpointManager) -> None:
        """StageCheckpointGuard marks stage failed on exception."""
        with pytest.raises(ValueError):
            with StageCheckpointGuard(checkpoint_manager, "failing_stage"):
                raise ValueError("Something went wrong")

        state = checkpoint_manager.load()
        assert state is not None
        assert state.stage_results["failing_stage"]["status"] == "failed"
        assert "ValueError" in state.stage_results["failing_stage"]["error"]

    def test_stage_checkpoint_guard_returns_manager(
        self, checkpoint_manager: CheckpointManager
    ) -> None:
        """StageCheckpointGuard __enter__ returns the manager."""
        with StageCheckpointGuard(checkpoint_manager, "test_stage") as mgr:
            assert mgr is checkpoint_manager

    def test_create_checkpoint_manager_helper(self, tmp_path: Path) -> None:
        """create_checkpoint_manager creates manager with standard layout."""
        manager = create_checkpoint_manager(tmp_path, "target1", "run-abc")
        assert manager.run_id == "run-abc"
        assert manager.checkpoint_dir == tmp_path / "target1" / "checkpoints"

    def test_create_checkpoint_manager_generates_run_id(self, tmp_path: Path) -> None:
        """create_checkpoint_manager generates run_id when not provided."""
        manager = create_checkpoint_manager(tmp_path, "target1")
        assert manager.run_id.startswith("run-")
        assert len(manager.run_id) > 10

    def test_generate_run_id_uniqueness(self) -> None:
        """generate_run_id produces unique IDs."""
        ids = {generate_run_id() for _ in range(100)}
        # All IDs should be unique (uuid suffix ensures this)
        assert len(ids) == 100

    def test_generate_run_id_format(self) -> None:
        """generate_run_id produces correctly formatted IDs."""
        run_id = generate_run_id()
        assert run_id.startswith("run-")
        parts = run_id.split("-")
        assert len(parts) == 3
        assert parts[1].isdigit()
        assert len(parts[2]) == 8

    def test_attempt_recovery_across_runs(self, tmp_path: Path) -> None:
        """attempt_recovery finds best checkpoint across multiple runs."""
        # attempt_recovery scans: output_dir / target_name / "checkpoints"
        output_dir = tmp_path / "output"
        target_name = "mytarget"

        mgr1 = create_checkpoint_manager(output_dir, target_name, "run-1")
        mgr1.mark_stage_complete("scope", {})
        time.sleep(0.01)

        mgr2 = create_checkpoint_manager(output_dir, target_name, "run-2")
        mgr2.mark_stage_complete("scope", {})
        mgr2.mark_stage_complete("subdomain_discovery", {})

        can_recover, state = attempt_recovery(output_dir, target_name)
        assert can_recover is True
        assert state is not None
        assert state.pipeline_run_id == "run-2"

    def test_attempt_recovery_no_checkpoints(self, tmp_path: Path) -> None:
        """attempt_recovery returns False when no checkpoints exist."""
        can_recover, state = attempt_recovery(tmp_path, "nonexistent")
        assert can_recover is False
        assert state is None

    def test_checkpoint_version_incrementing(self, checkpoint_manager: CheckpointManager) -> None:
        """Checkpoint version increments on each save."""
        state = CheckpointState(pipeline_run_id="test-run-001", checkpoint_version=0)
        checkpoint_manager.save(state)

        checkpoint_manager.mark_stage_complete("scope", {})
        loaded = checkpoint_manager.load()
        assert loaded is not None
        assert loaded.checkpoint_version == 1

        checkpoint_manager.mark_stage_complete("subdomain_discovery", {})
        loaded = checkpoint_manager.load()
        assert loaded is not None
        assert loaded.checkpoint_version == 2

    def test_load_latest_for_run_different_run_id(self, tmp_path: Path) -> None:
        """load_latest_for_run can load checkpoint for a different run_id."""
        mgr1 = CheckpointManager(tmp_path / "cp", "run-a")
        mgr1.mark_stage_complete("scope", {})

        mgr2 = CheckpointManager(tmp_path / "cp", "run-b")
        mgr2.mark_stage_complete("scope", {})
        mgr2.mark_stage_complete("subdomain_discovery", {})

        # mgr2 loads its own latest
        loaded = mgr2.load_latest_for_run("run-a")
        assert loaded is not None
        assert loaded.pipeline_run_id == "run-a"
        assert "scope" in loaded.completed_stages

    def test_serialization_of_sets_in_checkpoint_state(self) -> None:
        """CheckpointState serializes completed_stages as a list."""
        state = CheckpointState(
            pipeline_run_id="test",
            completed_stages=["b", "a", "c"],
        )
        data = state.to_dict()
        assert isinstance(data["completed_stages"], list)
        assert set(data["completed_stages"]) == {"a", "b", "c"}

    def test_deserialization_of_sets_in_checkpoint_state(self) -> None:
        """CheckpointState.from_dict restores completed_stages."""
        data = {
            "pipeline_run_id": "test",
            "completed_stages": ["scope", "recon"],
            "checkpoint_version": 1,
        }
        state = CheckpointState.from_dict(data)
        # from_dict converts completed_stages to a set
        assert isinstance(state.completed_stages, set)
        assert state.completed_stages == {"scope", "recon"}

    def test_ensure_run_dir_creates_directory(self, checkpoint_manager: CheckpointManager) -> None:
        """_ensure_run_dir creates the run directory."""
        assert not checkpoint_manager._run_dir.exists()
        checkpoint_manager._ensure_run_dir()
        assert checkpoint_manager._run_dir.exists()
        assert checkpoint_manager._run_dir.is_dir()

    def test_compute_checksum_deterministic(self) -> None:
        """_compute_checksum produces same result for same input."""
        data = '{"key": "value"}'
        cs1 = _compute_checksum(data)
        cs2 = _compute_checksum(data)
        assert cs1 == cs2

    def test_serialize_sets_function(self) -> None:
        """_serialize_sets converts sets to sorted lists."""
        data = {"hosts": {"b.com", "a.com"}, "nested": {"inner": {"z", "a"}}}
        result = _serialize_sets(data)
        assert result["hosts"] == ["a.com", "b.com"]
        assert result["nested"]["inner"] == ["a", "z"]


# ===========================================================================
# 5. TestMergeFindingsWithNuclei
# ===========================================================================


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
