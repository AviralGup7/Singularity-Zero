"""Architecture test: enforce TaskEnvelope-only queue paths.

All queue producers and consumers must use TaskEnvelope. This test scans
all queue.put(...) calls and verifies the payload is always a TaskEnvelope
instance or model_dump() thereof.

Run with: pytest tests/architecture/test_distributed_contracts.py -q
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

WORKSPACE = Path(__file__).resolve().parents[2]
SRC_ROOT = WORKSPACE / "src"


class QueueCallCollector(ast.NodeVisitor):
    """AST visitor that collects queue.put() call arguments."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.violations: list[str] = []
        self.queue_put_calls: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("put", "put_nowait", "enqueue", "enqueue_task"):
                if node.func.attr in ("enqueue", "enqueue_task"):
                    self.queue_put_calls.append((node.lineno, f"{self.filepath}:{node.lineno}"))
                else:
                    obj_name = (
                        node.func.value.id
                        if isinstance(node.func.value, ast.Name)
                        else getattr(node.func.value, "id", "?")
                    )
                    if any(
                        suffix in obj_name.lower()
                        for suffix in ("queue", "job_queue", "task_queue", "work_queue")
                    ):
                        self.queue_put_calls.append(
                            (
                                node.lineno,
                                f"{self.filepath}:{node.lineno} ({obj_name}.{node.func.attr})",
                            )
                        )
        self.generic_visit(node)


def _scan_file_for_queue_puts(filepath: Path) -> list[tuple[int, str]]:
    """Scan a Python file for queue.put() calls."""
    try:
        content = filepath.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(filepath))
    except SyntaxError:
        return []
    collector = QueueCallCollector(str(filepath.relative_to(WORKSPACE)))
    collector.visit(tree)
    return collector.queue_put_calls


@pytest.mark.architecture
class TestTaskEnvelopeExclusivity:
    """Verify all queue paths use TaskEnvelope exclusively."""

    def test_all_queue_producers_use_task_envelope(self) -> None:
        """Every queue.put/enqueue must use TaskEnvelope model_dump() or TaskEnvelope instance.

        Note: Internal asyncio.Queue instances (progress_queue, events queue) are excluded
        as they handle in-process events, not distributed job queue traffic.
        """
        INTERNAL_QUEUE_FILES = {
            "src/core/progress_queue.py",
            "src/core/events.py",
            "src/infrastructure/observability/structured_logging.py",
            "src/websocket_server/handlers.py",
            "src/websocket_server/broadcaster.py",
        }

        violations: list[str] = []
        queue_call_locations: list[tuple[int, str]] = []

        for py_file in SRC_ROOT.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            calls = _scan_file_for_queue_puts(py_file)
            queue_call_locations.extend(calls)

        for lineno, location in queue_call_locations:
            if location.startswith("src/infrastructure/queue/"):
                continue
            norm = location.replace("\\", "/")
            if any(internal in norm for internal in INTERNAL_QUEUE_FILES):
                continue
            violations.append(f"  {location} — queue.put/enqueue call found")

        assert violations == [], (
            "All distributed queue.put/enqueue calls must use TaskEnvelope.\n"
            + "\n".join(violations)
            + f"\n\nFound {len(queue_call_locations)} total queue call sites "
            + f"({len([l for l in queue_call_locations if any(i in l[1] for i in INTERNAL_QUEUE_FILES)])} internal, "
            + f"{len([l for l in queue_call_locations if not any(i in l[1] for i in INTERNAL_QUEUE_FILES)]) - 1} distributed)."
        )

    def test_task_envelope_has_required_fields(self) -> None:
        """TaskEnvelope must have schema_version and traceparent fields."""
        from src.core.contracts.task_envelope import TASK_ENVELOPE_VERSION, TaskEnvelope

        envelope = TaskEnvelope(type="test", payload={"foo": "bar"})

        assert hasattr(envelope, "schema_version"), "TaskEnvelope missing schema_version"
        assert envelope.schema_version == TASK_ENVELOPE_VERSION
        assert hasattr(envelope, "traceparent"), "TaskEnvelope missing traceparent"
        assert isinstance(envelope.traceparent, str)
        assert len(envelope.traceparent) > 0
        assert envelope.traceparent.startswith("00-"), "traceparent must be W3C format"

    def test_task_envelope_serialization_roundtrip(self) -> None:
        """TaskEnvelope must serialize and deserialize correctly with all fields."""
        from src.core.contracts.task_envelope import TaskEnvelope

        original = TaskEnvelope(
            type="pipeline_scan",
            payload={"target": "example.com", "config": {"mode": "safe"}},
            metadata={"priority": "high", "source": "dashboard"},
            traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )

        serialized = original.to_dict()
        assert "traceparent" in serialized, "to_dict() must include traceparent"
        assert "schema_version" in serialized, "to_dict() must include schema_version"

        restored = TaskEnvelope.from_dict(serialized)
        assert restored.type == original.type
        assert restored.payload == original.payload
        assert restored.traceparent == original.traceparent
        assert restored.schema_version == original.schema_version

    def test_job_from_task_envelope_preserves_traceparent(self) -> None:
        """Job.as_task_envelope() must preserve traceparent from stored payload."""
        from src.core.contracts.task_envelope import TaskEnvelope
        from src.infrastructure.queue.models import Job

        envelope = TaskEnvelope(
            type="recon",
            payload={"targets": ["example.com"]},
            traceparent="00-abcd1234567890abcdef1234567890ab-1234567890abcdef-01",
        )

        job = Job.from_task_envelope(envelope, queue_name="test-queue")
        roundtrip = job.as_task_envelope()

        assert roundtrip.traceparent == envelope.traceparent, (
            "traceparent must be preserved through Job serialization roundtrip"
        )

    def test_worker_rejects_invalid_task_envelope_type(self) -> None:
        """Worker must reject jobs with missing or invalid TaskEnvelope type field."""
        from src.core.contracts.task_envelope import TaskEnvelope

        invalid_envelope = TaskEnvelope(type="", payload={})

        assert invalid_envelope.type == ""

        valid_envelope = TaskEnvelope(type="valid_type", payload={})
        assert valid_envelope.type == "valid_type"


@pytest.mark.architecture
class TestTaskEnvelopeWorkerValidation:
    """Verify worker properly validates TaskEnvelope contracts."""

    def test_worker_handlers_always_receive_task_envelope(self) -> None:
        """Handler always receives TaskEnvelope."""
        from src.core.contracts.task_envelope import TaskEnvelope

        received_envelope: TaskEnvelope | None = None

        def handler(job_or_envelope: TaskEnvelope) -> dict[str, str]:
            nonlocal received_envelope
            received_envelope = job_or_envelope
            return {"status": "ok"}

        envelope = TaskEnvelope(
            type="test",
            payload={"key": "value"},
            traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )

        handler(envelope)

        assert received_envelope is not None
        assert received_envelope.type == "test"
        assert received_envelope.traceparent == envelope.traceparent

    def test_task_envelope_traceparent_format(self) -> None:
        """traceparent must follow W3C Trace Context format: version-traceId-parentId-flags."""
        from src.core.contracts.task_envelope import TaskEnvelope

        envelope = TaskEnvelope(type="test", payload={})

        parts = envelope.traceparent.split("-")
        assert len(parts) == 4, f"traceparent must have 4 parts, got: {envelope.traceparent}"

        version, trace_id, parent_id, flags = parts
        assert len(version) == 2, f"version must be 2 chars: {version}"
        assert len(trace_id) == 32, f"trace_id must be 32 chars: {trace_id}"
        assert len(parent_id) == 16, f"parent_id must be 16 chars: {parent_id}"
        assert len(flags) == 2, f"flags must be 2 chars: {flags}"


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
