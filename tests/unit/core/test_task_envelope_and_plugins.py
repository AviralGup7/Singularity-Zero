import pytest

from src.core.contracts.task_envelope import TASK_ENVELOPE_VERSION, TaskEnvelope, TaskRetryPolicy
from src.infrastructure.queue.models import Job
from src.pipeline.services.plugin_catalog import list_registered_stage_runners, resolve_stage_runner


@pytest.mark.unit
def test_task_envelope_round_trip() -> None:
    envelope = TaskEnvelope(
        type="nuclei_scan",
        payload={"targets": ["https://example.com"]},
        metadata={"tenant": "acme"},
        retry_policy=TaskRetryPolicy(max_attempts=5),
        correlation_id="corr-123",
    )

    restored = TaskEnvelope.from_dict(envelope.to_dict())

    assert restored.type == "nuclei_scan"
    assert restored.payload["targets"] == ["https://example.com"]
    assert restored.retry_policy.max_attempts == 5
    assert restored.schema_version == TASK_ENVELOPE_VERSION


@pytest.mark.unit
def test_job_task_envelope_conversion() -> None:
    envelope = TaskEnvelope(
        type="validation",
        payload={"url": "https://example.com"},
        metadata={"correlation_id": "corr-777"},
    )

    job = Job.from_task_envelope(envelope, queue_name="default")
    reconstructed = job.as_task_envelope()

    assert reconstructed.type == "validation"
    assert reconstructed.payload["url"] == "https://example.com"
    assert reconstructed.correlation_id == "corr-777"


@pytest.mark.unit
def test_plugin_registry_exposes_stage_runner_categories() -> None:
    runners = list_registered_stage_runners()

    assert "subdomains" in runners["recon_provider"]
    assert "nuclei" in runners["scanner"]
    assert "validation" in runners["validator"]
    assert callable(resolve_stage_runner("reporting"))
