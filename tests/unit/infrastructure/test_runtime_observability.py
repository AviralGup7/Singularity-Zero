"""Tests for runtime observability metrics."""

from __future__ import annotations

import time

import pytest

from src.infrastructure.observability.metrics import (
    get_metrics,
    reset_metrics_instance,
)


@pytest.fixture(autouse=True)
def _clean_metrics():
    """Ensure fresh MetricsRegistry for each test."""
    reset_metrics_instance()
    yield
    reset_metrics_instance()


class TestRuntimeObservabilityMetrics:
    """Verify that runtime observability metrics are registered."""

    def test_stage_failure_count_registered(self):
        metrics = get_metrics()
        counter = metrics.counter("stage_failure_count", "test")
        assert counter.name == "cyber_pipeline_stage_failure_count"

    def test_pipeline_run_count_registered(self):
        metrics = get_metrics()
        counter = metrics.counter("pipeline_run_count", "test")
        assert counter.name == "cyber_pipeline_pipeline_run_count"

    def test_pipeline_success_count_registered(self):
        metrics = get_metrics()
        counter = metrics.counter("pipeline_success_count", "test")
        assert counter.name == "cyber_pipeline_pipeline_success_count"

    def test_analyzer_execution_count_registered(self):
        metrics = get_metrics()
        counter = metrics.counter("analyzer_execution_count", "test")
        assert counter.name == "cyber_pipeline_analyzer_execution_count"

    def test_analyzer_failure_count_registered(self):
        metrics = get_metrics()
        counter = metrics.counter("analyzer_failure_count", "test")
        assert counter.name == "cyber_pipeline_analyzer_failure_count"

    def test_analyzer_duration_seconds_registered(self):
        metrics = get_metrics()
        hist = metrics.histogram("analyzer_duration_seconds", "test")
        assert hist.name == "cyber_pipeline_analyzer_duration_seconds"

    def test_analyzer_active_count_registered(self):
        metrics = get_metrics()
        gauge = metrics.gauge("analyzer_active_count", "test")
        assert gauge.name == "cyber_pipeline_analyzer_active_count"

    def test_process_rss_mb_registered(self):
        metrics = get_metrics()
        gauge = metrics.gauge("process_rss_mb", "test")
        assert gauge.name == "cyber_pipeline_process_rss_mb"

    def test_process_thread_count_registered(self):
        metrics = get_metrics()
        gauge = metrics.gauge("process_thread_count", "test")
        assert gauge.name == "cyber_pipeline_process_thread_count"

    def test_asyncio_task_count_registered(self):
        metrics = get_metrics()
        gauge = metrics.gauge("asyncio_task_count", "test")
        assert gauge.name == "cyber_pipeline_asyncio_task_count"

    def test_queue_pending_count_registered(self):
        metrics = get_metrics()
        gauge = metrics.gauge("queue_pending_count", "test")
        assert gauge.name == "cyber_pipeline_queue_pending_count"

    def test_queue_dead_letter_count_registered(self):
        metrics = get_metrics()
        gauge = metrics.gauge("queue_dead_letter_count", "test")
        assert gauge.name == "cyber_pipeline_queue_dead_letter_count"


class TestAnalyzerMetricsInstrumentation:
    """Test the _get_analyzer_metrics helper."""

    def test_get_analyzer_metrics_returns_dict(self):
        from src.analysis.plugin_runtime._runner import _get_analyzer_metrics

        result = _get_analyzer_metrics()
        assert result is not None
        assert "execution_count" in result
        assert "failure_count" in result
        assert "duration" in result
        assert "active" in result

    def test_get_analyzer_metrics_tracks_execution(self):
        from src.analysis.plugin_runtime._runner import _get_analyzer_metrics

        metrics = _get_analyzer_metrics()
        initial = metrics["execution_count"].value
        metrics["execution_count"].inc()
        assert metrics["execution_count"].value == initial + 1

    def test_get_analyzer_metrics_tracks_failure(self):
        from src.analysis.plugin_runtime._runner import _get_analyzer_metrics

        metrics = _get_analyzer_metrics()
        initial = metrics["failure_count"].value
        metrics["failure_count"].inc()
        assert metrics["failure_count"].value == initial + 1

    def test_get_analyzer_metrics_active_gauge(self):
        from src.analysis.plugin_runtime._runner import _get_analyzer_metrics

        metrics = _get_analyzer_metrics()
        initial = metrics["active"].value
        metrics["active"].inc()
        assert metrics["active"].value == initial + 1
        metrics["active"].dec()
        assert metrics["active"].value == initial


class TestEventSubscriberPerStageFailure:
    """Test that stage_failure_count increments on stage failure."""

    def test_stage_failure_increments_counter(self):
        from src.core.events import EventBus, EventType, PipelineEvent
        from src.infrastructure.observability.event_subscribers import (
            register_event_metrics_subscribers,
        )

        bus = EventBus()
        register_event_metrics_subscribers(bus)

        metrics = get_metrics()
        counter = metrics.counter("stage_failure_count", "test")
        initial = counter.value

        PipelineEvent(
            event_type=EventType.STAGE_FAILED,
            source="stage.subdomains",
            data={},
        )
        bus.emit(EventType.STAGE_FAILED, source="stage.subdomains", data={})

        assert counter.value == initial + 1


class TestSystemSampler:
    """Test the SystemSampler class."""

    def test_sampler_initialization(self):
        from src.infrastructure.observability.system_sampler import SystemSampler

        sampler = SystemSampler(interval_seconds=1.0)
        assert sampler._interval == 1.0
        assert sampler._thread is None

    def test_sampler_start_stop(self):
        from src.infrastructure.observability.system_sampler import SystemSampler

        sampler = SystemSampler(interval_seconds=0.1)
        sampler.start()
        assert sampler._thread is not None
        assert sampler._thread.is_alive()
        time.sleep(0.2)
        sampler.stop()
        assert not sampler._thread.is_alive()

    def test_sampler_singleton(self):
        from src.infrastructure.observability.system_sampler import get_system_sampler

        s1 = get_system_sampler()
        s2 = get_system_sampler()
        assert s1 is s2
