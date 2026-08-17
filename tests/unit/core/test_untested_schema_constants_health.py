"""Coverage for schema validator, constants, param categories, and health contracts."""

from __future__ import annotations

import asyncio

import pytest

from src.core.constants import (
    CONFIDENCE_DEGRADATION_THRESHOLD,
    DEFAULT_ALLOWED_ORIGINS,
    HEALTH_SCORE_MULTIPLIERS,
    MAX_ITERATION_LIMIT,
    SCAN_QUALITY_WEIGHTS,
    SEVERITY_PRIORITY_SCORES,
    SEVERITY_SCORES,
)
from src.core.contracts.health import (
    CorrectionEvent,
    CorrectiveAction,
    CorrectiveActionRegistry,
    HealthComponent,
    HealthFinding,
    HealthMetric,
    HealthStatus,
    PipelineHealthSnapshot,
)
from src.core.contracts.param_categories import ParamCategory
from src.core.contracts.schema_validator import (
    SchemaValidationError,
    validate_analysis_payload,
    validate_decision_payload,
    validate_detection_payload,
    validate_execution_payload,
    validate_recon_payload,
)


@pytest.mark.unit
@pytest.mark.parametrize("member", list(ParamCategory))
def test_param_category_values_are_nonempty_slugs(member: ParamCategory) -> None:
    assert member.value
    assert member.value == member.value.lower()
    assert " " not in member.value


@pytest.mark.unit
def test_severity_maps_cover_standard_labels() -> None:
    for label in ("critical", "high", "medium", "low"):
        assert label in SEVERITY_SCORES
        assert label in SEVERITY_PRIORITY_SCORES
        assert SEVERITY_SCORES[label] >= SEVERITY_PRIORITY_SCORES[label]


@pytest.mark.unit
def test_scan_quality_weights_sum_to_one() -> None:
    assert pytest.approx(sum(SCAN_QUALITY_WEIGHTS.values()), abs=1e-9) == 1.0


@pytest.mark.unit
def test_pipeline_constants_are_positive() -> None:
    assert MAX_ITERATION_LIMIT >= 1
    assert 0 < CONFIDENCE_DEGRADATION_THRESHOLD <= 1
    assert all(v > 0 for v in HEALTH_SCORE_MULTIPLIERS.values())
    assert all(origin.startswith("http") for origin in DEFAULT_ALLOWED_ORIGINS)


@pytest.mark.unit
def test_validate_recon_payload_accepts_absolute_urls() -> None:
    payload = {"urls": ["https://a.example/x"], "live_hosts": ["a.example"]}
    assert validate_recon_payload(payload) is payload


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "notaurl", "/relative", None])
def test_validate_recon_payload_rejects_bad_urls(bad) -> None:
    with pytest.raises(SchemaValidationError):
        validate_recon_payload({"urls": [bad]})


@pytest.mark.unit
def test_validate_recon_payload_requires_mapping() -> None:
    with pytest.raises(SchemaValidationError, match="mapping"):
        validate_recon_payload(["nope"])  # type: ignore[arg-type]


@pytest.mark.unit
def test_validate_detection_payload_checks_nested_urls() -> None:
    payload = {"xss": [{"url": "https://a.example/q"}]}
    assert validate_detection_payload(payload) is payload
    with pytest.raises(SchemaValidationError):
        validate_detection_payload({"xss": [{"url": "bad"}]})


@pytest.mark.unit
def test_validate_analysis_payload_requires_finding_urls() -> None:
    ok = {"findings": [{"url": "https://a.example"}]}
    assert validate_analysis_payload(ok) is ok
    with pytest.raises(SchemaValidationError):
        validate_analysis_payload({"findings": [{"url": "x"}]})


@pytest.mark.unit
def test_validate_decision_payload_requires_decision_field() -> None:
    ok = {"findings": [{"decision": "keep"}]}
    assert validate_decision_payload(ok) is ok
    with pytest.raises(SchemaValidationError, match="decision"):
        validate_decision_payload({"findings": [{}]})


@pytest.mark.unit
def test_validate_execution_payload_requires_results_mapping() -> None:
    ok = {"results": {}, "errors": []}
    assert validate_execution_payload(ok) is ok
    with pytest.raises(SchemaValidationError):
        validate_execution_payload({"results": [], "errors": []})


@pytest.mark.unit
def test_health_snapshot_serializes_enums() -> None:
    finding = HealthFinding(
        component=HealthComponent.QUEUE,
        status=HealthStatus.DEGRADED,
        reason="lag",
        action=CorrectiveAction.NOOP,
        metric="depth",
    )
    metric = HealthMetric(component=HealthComponent.QUEUE, name="depth", value=3)
    snap = PipelineHealthSnapshot(
        status=HealthStatus.DEGRADED,
        metrics=[metric],
        findings=[finding],
        corrections=[],
    )
    data = snap.as_dict()
    assert data["status"] == "degraded"
    assert data["metrics"][0]["component"] == "queue"
    assert data["findings"][0]["action"] == "noop"
    assert isinstance(data["generated_at"], float)


@pytest.mark.unit
def test_corrective_registry_escalates_when_unregistered() -> None:
    registry = CorrectiveActionRegistry()
    finding = HealthFinding(
        component=HealthComponent.WORKER,
        status=HealthStatus.CRITICAL,
        reason="dead",
        action=CorrectiveAction.RESTART_WORKER,
        metric="alive",
    )
    event = asyncio.run(registry.execute(finding))
    assert event.success is False
    assert event.action == CorrectiveAction.ESCALATE_ANALYST
    assert registry.history[-1] is event


@pytest.mark.unit
def test_corrective_registry_records_handler_success() -> None:
    registry = CorrectiveActionRegistry()

    def handler(finding: HealthFinding) -> CorrectionEvent:
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=finding.action,
            success=True,
            message="ok",
            component=finding.component,
        )

    registry.register(CorrectiveAction.NOOP, handler)
    finding = HealthFinding(
        component=HealthComponent.PIPELINE_STAGE,
        status=HealthStatus.OK,
        reason="fine",
        action=CorrectiveAction.NOOP,
        metric="x",
    )
    event = asyncio.run(registry.execute(finding))
    assert event.success is True
    assert event.message == "ok"


@pytest.mark.unit
def test_corrective_registry_captures_handler_exceptions() -> None:
    registry = CorrectiveActionRegistry()

    def boom(_finding: HealthFinding) -> CorrectionEvent:
        raise RuntimeError("handler exploded")

    registry.register(CorrectiveAction.FLUSH_BLOOM_FILTER, boom)
    finding = HealthFinding(
        component=HealthComponent.BLOOM_MESH,
        status=HealthStatus.CRITICAL,
        reason="full",
        action=CorrectiveAction.FLUSH_BLOOM_FILTER,
        metric="fill",
    )
    event = asyncio.run(registry.execute(finding))
    assert event.success is False
    assert "exploded" in event.message


@pytest.mark.unit
def test_history_is_capped_at_one_hundred() -> None:
    registry = CorrectiveActionRegistry()
    finding = HealthFinding(
        component=HealthComponent.QUEUE,
        status=HealthStatus.OK,
        reason="n",
        action=CorrectiveAction.NOOP,
        metric="n",
    )
    for _ in range(120):
        asyncio.run(registry.execute(finding))
    assert len(registry.history) == 100
