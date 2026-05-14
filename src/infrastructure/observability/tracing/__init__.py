"""Distributed tracing system for the cyber security test pipeline.

Provides OpenTelemetry-compatible span creation, trace context propagation,
parent-child span relationships, error annotation, sampling configuration,
and in-memory/OTLP exporters.

Usage:
    from src.infrastructure.observability.tracing import get_tracer

    tracer = get_tracer()
    with tracer.start_span("process_job") as span:
        span.set_attribute("job_id", "abc123")
        span.set_attribute("target", "example.com")
"""

# Models
# Exporters
from src.infrastructure.observability.tracing.exporters import (
    InMemoryExporter,
    OTLPExporter,
)
from src.infrastructure.observability.tracing.models import (
    Span,
    SpanEvent,
    SpanLink,
    SpanStatus,
    _current_span,
    _current_trace_id,
)

# Sampling
from src.infrastructure.observability.tracing.sampling import SamplingDecision

# Tracer
from src.infrastructure.observability.tracing.tracer import Tracer, get_tracer

__all__ = [
    "Span",
    "SpanEvent",
    "SpanLink",
    "SpanStatus",
    "SamplingDecision",
    "InMemoryExporter",
    "OTLPExporter",
    "Tracer",
    "get_tracer",
]
