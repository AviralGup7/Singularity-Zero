"""Trace-aware loggers for pipeline code."""

from __future__ import annotations

import logging


class TraceContextFilter(logging.Filter):
    """Attach current OpenTelemetry identifiers to every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        trace_id = ""
        span_id = ""
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            ctx = span.get_span_context()
            if getattr(ctx, "is_valid", False):
                trace_id = f"{ctx.trace_id:032x}"
                span_id = f"{ctx.span_id:016x}"
        except Exception:
            pass

        record.trace_id = trace_id
        record.span_id = span_id
        return True


_FILTER = TraceContextFilter()


def get_pipeline_logger(name: str) -> logging.Logger:
    """Return a logger that enriches records with trace_id and span_id."""
    logger = logging.getLogger(name)
    if not any(isinstance(existing, TraceContextFilter) for existing in logger.filters):
        logger.addFilter(_FILTER)
    return logger


def install_trace_log_filter(root: logging.Logger | None = None) -> None:
    """Install trace enrichment on an existing root logger."""
    target = root or logging.getLogger()
    if not any(isinstance(existing, TraceContextFilter) for existing in target.filters):
        target.addFilter(_FILTER)

