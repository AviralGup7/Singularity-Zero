"""Coverage for previously untested persistence models and observability types."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.core.checkpoint.manager import CheckpointData
from src.core.observability.metrics import (
    HealthCheckRegistry,
    HealthStatus,
    MetricsCollector,
    Span,
    Tracer,
    get_metrics,
    get_tracer,
)
from src.core.persistence.base import (
    AndSpecification,
    BaseModel,
    OptimisticLockMixin,
    Page,
    PaginationParams,
    Result,
    SoftDeleteMixin,
    Specification,
)
from src.core.persistence.transaction import RetryPolicy, RetryStrategy


class _EvenSpec(Specification[int]):
    def is_satisfied_by(self, candidate: int) -> bool:
        return candidate % 2 == 0


class _PositiveSpec(Specification[int]):
    def is_satisfied_by(self, candidate: int) -> bool:
        return candidate > 0


@pytest.mark.unit
def test_pagination_params_clamp_and_offset() -> None:
    params = PaginationParams(page=0, size=0)
    assert params.page == 1
    assert params.size == 1
    assert params.offset == 0
    wide = PaginationParams(page=3, size=500)
    assert wide.size == 100
    assert wide.offset == 200


@pytest.mark.unit
def test_page_total_pages_and_to_dict() -> None:
    page = Page(items=["a", "b"], total=21, page=2, size=10)
    assert page.total_pages == 3
    payload = page.to_dict()
    assert payload["total"] == 21
    assert payload["total_pages"] == 3
    empty = Page(items=[], total=0, page=1, size=20)
    assert empty.total_pages == 0


@pytest.mark.unit
def test_result_ok_err_unwrap() -> None:
    ok = Result.ok(42)
    assert ok.success is True
    assert ok.unwrap() == 42
    assert ok.unwrap_or(0) == 42
    err = Result.err("missing", code="not_found")
    assert err.success is False
    assert err.error_code == "not_found"
    assert err.unwrap_or(7) == 7
    with pytest.raises(ValueError, match="missing"):
        err.unwrap()


@pytest.mark.unit
def test_base_model_roundtrip() -> None:
    model = BaseModel()
    dumped = model.to_dict()
    restored = BaseModel.from_dict(dumped)
    assert restored.id == model.id
    assert restored.version == 1
    assert isinstance(restored.created_at, datetime)
    fresh = BaseModel.from_dict({})
    assert fresh.id
    assert fresh.version == 1


@pytest.mark.unit
def test_soft_delete_and_optimistic_lock() -> None:
    row = SoftDeleteMixin()
    assert row.is_deleted is False
    row.soft_delete("alice")
    assert row.is_deleted is True
    assert row.deleted_by == "alice"
    row.restore()
    assert row.is_deleted is False
    lock = OptimisticLockMixin()
    assert lock.check_version(1) is True
    lock.increment_version()
    assert lock.version == 2
    assert lock.check_version(1) is False


@pytest.mark.unit
def test_specification_and_or_not() -> None:
    spec = _EvenSpec().and_(_PositiveSpec())
    assert spec.is_satisfied_by(4) is True
    assert spec.is_satisfied_by(-2) is False
    assert spec.is_satisfied_by(3) is False
    assert _EvenSpec().or_(_PositiveSpec()).is_satisfied_by(3) is True
    assert _EvenSpec().not_().is_satisfied_by(3) is True
    assert isinstance(_EvenSpec().and_(_PositiveSpec()), AndSpecification)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("strategy", "attempt", "expected"),
    [
        (RetryStrategy.FIXED, 1, 1.0),
        (RetryStrategy.FIXED, 4, 1.0),
        (RetryStrategy.EXPONENTIAL, 1, 1.0),
        (RetryStrategy.EXPONENTIAL, 4, 8.0),
        (RetryStrategy.LINEAR, 3, 3.0),
    ],
)
def test_retry_policy_delay(strategy: RetryStrategy, attempt: int, expected: float) -> None:
    policy = RetryPolicy(base_delay=1.0, max_delay=60.0, strategy=strategy)
    assert policy.calculate_delay(attempt) == expected


@pytest.mark.unit
def test_retry_policy_caps_exponential_at_max_delay() -> None:
    policy = RetryPolicy(base_delay=10.0, max_delay=15.0, strategy=RetryStrategy.EXPONENTIAL)
    assert policy.calculate_delay(5) == 15.0


@pytest.mark.unit
def test_metrics_key_prometheus_and_singleton() -> None:
    collector = MetricsCollector()
    assert collector._make_key("hits", None) == "hits"
    assert collector._make_key("hits", {"code": "200", "method": "GET"}) == (
        "hits{code=200,method=GET}"
    )
    assert collector.get_all() == []
    assert collector.to_prometheus() == ""
    first = get_metrics()
    assert get_metrics() is first


@pytest.mark.unit
def test_span_tracer_and_health_registry() -> None:
    tracer = Tracer()
    parent = tracer.start_span("root")
    child = tracer.start_span("child", parent=parent)
    parent.set_tag("svc", "api")
    parent.log("start", detail="ok")
    parent.finish()
    assert child.trace_id == parent.trace_id
    assert child.parent_span_id == parent.span_id
    assert parent.end_time is not None
    assert parent.tags["svc"] == "api"
    assert parent.logs[0]["event"] == "start"
    carrier: dict[str, str] = {}
    tracer.inject(parent, carrier)
    extracted = tracer.extract(carrier)
    assert extracted is not None
    assert extracted.trace_id == parent.trace_id
    assert tracer.extract({}) is None
    assert get_tracer() is get_tracer()

    registry = HealthCheckRegistry()
    import asyncio

    empty = asyncio.run(registry.run_all())
    assert empty["status"] == HealthStatus.HEALTHY.value
    assert empty["checks"] == {}
    assert HealthStatus.DEGRADED.value == "degraded"


@pytest.mark.unit
def test_checkpoint_data_json_roundtrip_and_checksum() -> None:
    original = CheckpointData(
        run_id="run-1",
        version=2,
        timestamp=123.0,
        stages={"recon": {"ok": True}},
        artifacts={"report": "abc"},
        metadata={"n": 1},
    )
    restored = CheckpointData.from_json(original.to_json())
    assert restored.run_id == "run-1"
    assert restored.stages["recon"]["ok"] is True
    assert restored.checksum() == original.checksum()
    other = CheckpointData(run_id="run-1", version=3, timestamp=123.0)
    assert other.checksum() != original.checksum()
