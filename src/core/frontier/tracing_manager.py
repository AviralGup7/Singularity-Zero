"""OpenTelemetry tracing facade with local span persistence.

This module is intentionally import-safe: if OpenTelemetry is unavailable or
misconfigured, callers still get no-op tracing primitives and the pipeline keeps
running.
"""

from __future__ import annotations

import functools
import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from urllib import error, request

DEFAULT_OTLP_ENDPOINT = "http://localhost:4318/v1/traces"
DEFAULT_TRACE_DB = Path("output") / "traces.db"


class NoOpSpan:
    """Small span shim used when OpenTelemetry is not importable."""

    def set_attribute(self, key: str, value: Any) -> None:
        _ = key, value

    def set_status(self, status: Any) -> None:
        _ = status

    def record_exception(self, exc: BaseException) -> None:
        _ = exc


class SQLiteSpanExporter:
    """OpenTelemetry SpanExporter-compatible SQLite writer."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path or os.getenv("OTEL_LOCAL_SPAN_DB") or DEFAULT_TRACE_DB)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS spans (
                    trace_id TEXT NOT NULL,
                    span_id TEXT NOT NULL,
                    parent_span_id TEXT,
                    name TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    stage_name TEXT,
                    start_time_unix_nano INTEGER NOT NULL,
                    end_time_unix_nano INTEGER NOT NULL,
                    duration_ms REAL NOT NULL,
                    status TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    PRIMARY KEY (trace_id, span_id)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_spans_trace_start ON spans(trace_id, start_time_unix_nano)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_spans_stage_start ON spans(stage_name, start_time_unix_nano)"
            )

    def export(self, spans: Any) -> Any:
        success_code: Any = 0
        try:
            from opentelemetry.sdk.trace.export import SpanExportResult

            success_code = SpanExportResult.SUCCESS
        except Exception:  # noqa: S110
            pass

        rows = []
        for span in spans:
            ctx = span.get_span_context()
            parent = getattr(span, "parent", None)
            attrs = dict(getattr(span, "attributes", {}) or {})
            resource_attrs = dict(getattr(getattr(span, "resource", None), "attributes", {}) or {})
            start_ns = int(getattr(span, "start_time", 0) or 0)
            end_ns = int(getattr(span, "end_time", 0) or start_ns)
            status = getattr(getattr(span, "status", None), "status_code", None)
            status_name = str(getattr(status, "name", "OK") or "OK")
            if status_name == "UNSET":
                status_name = "OK"
            rows.append(
                (
                    f"{ctx.trace_id:032x}",
                    f"{ctx.span_id:016x}",
                    f"{parent.span_id:016x}" if parent else None,
                    str(getattr(span, "name", "")),
                    str(resource_attrs.get("service.name", "cyber-pipeline")),
                    str(attrs.get("stage_name", "") or ""),
                    start_ns,
                    end_ns,
                    max(0.0, (end_ns - start_ns) / 1_000_000.0),
                    status_name,
                    json.dumps(attrs, default=str, sort_keys=True),
                    json.dumps(
                        [
                            {
                                "name": getattr(event, "name", ""),
                                "timestamp": getattr(event, "timestamp", None),
                                "attributes": dict(getattr(event, "attributes", {}) or {}),
                            }
                            for event in (getattr(span, "events", []) or [])
                        ],
                        default=str,
                    ),
                    time.time(),
                )
            )

        if rows:
            with self._lock, sqlite3.connect(self.db_path) as conn:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO spans (
                        trace_id, span_id, parent_span_id, name, service_name, stage_name,
                        start_time_unix_nano, end_time_unix_nano, duration_ms, status,
                        attributes_json, events_json, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        return success_code

    def shutdown(self) -> None:
        return None


class TracingManager:
    """Owns OpenTelemetry setup, local trace storage, and context propagation."""

    def __init__(
        self,
        endpoint: str | None = None,
        db_path: str | Path | None = None,
        service_name: str = "cyber-pipeline",
    ) -> None:
        self.endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", DEFAULT_OTLP_ENDPOINT)
        self.service_name = service_name
        self._status_cache: str = ""
        self.local_exporter = SQLiteSpanExporter(db_path)
        self.otel_available = False
        self.initialization_error = ""
        self._trace: Any = None
        self._propagate: Any = None
        self._status_cls: Any = None
        self._status_code_cls: Any = None
        self._tracer: Any = None
        self._provider: Any = None
        self._init_otel()

    def _init_otel(self) -> None:
        try:
            from opentelemetry import propagate, trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
            from opentelemetry.trace import Status, StatusCode
        except Exception as exc:
            self.initialization_error = str(exc)
            return

        try:
            provider = TracerProvider(resource=Resource.create({"service.name": self.service_name}))
            provider.add_span_processor(SimpleSpanProcessor(cast(Any, self.local_exporter)))
            provider.add_span_processor(
                BatchSpanProcessor(
                    OTLPSpanExporter(endpoint=self.endpoint, timeout=5),
                    max_queue_size=2048,
                    max_export_batch_size=128,
                )
            )
            try:
                trace.set_tracer_provider(provider)
            except Exception:  # noqa: S110
                pass

            self._trace = trace
            self._propagate = propagate
            self._status_cls = Status
            self._status_code_cls = StatusCode
            self._provider = provider
            self._tracer = provider.get_tracer("cyber-pipeline")
            self.otel_available = True
        except Exception as exc:
            self.initialization_error = str(exc)
            self.otel_available = False

    @contextmanager
    def start_span(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        parent_headers: Mapping[str, str] | None = None,
    ) -> Iterator[Any]:
        if not self.otel_available or self._tracer is None:
            yield NoOpSpan()
            return

        context = None
        if parent_headers and self._propagate is not None:
            try:
                context = self._propagate.extract(dict(parent_headers))
            except Exception:  # noqa: S110
                context = None

        with self._tracer.start_as_current_span(
            str(name),
            context=context,
            attributes=dict(attributes or {}),
        ) as span:
            yield span

    def traced(
        self, stage_name: str | None = None
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for async or sync stage runner functions."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            name = stage_name or getattr(func, "__name__", "stage")

            import inspect

            is_async = inspect.iscoroutinefunction(func)

            if is_async:

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    with self.start_stage_span(str(name), *args, **kwargs) as span:
                        try:
                            result = await func(*args, **kwargs)
                            self.record_stage_result(span, result)
                            return result
                        except Exception as exc:
                            self.record_exception(span, exc)
                            raise

                return async_wrapper

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                with self.start_stage_span(str(name), *args, **kwargs) as span:
                    try:
                        result = func(*args, **kwargs)
                        self.record_stage_result(span, result)
                        return result
                    except Exception as exc:
                        self.record_exception(span, exc)
                        raise

            return sync_wrapper

        return decorator

    @contextmanager
    def start_stage_span(self, stage_name: str, *args: Any, **kwargs: Any) -> Iterator[Any]:
        ctx = next(
            (arg for arg in args if hasattr(arg, "result") and hasattr(arg, "scope_entries")), None
        )
        target_count = 0
        scope_size = 0
        if ctx is not None:
            try:
                target_count = len(
                    getattr(ctx, "priority_urls", []) or getattr(ctx, "urls", []) or []
                )
            except Exception:  # noqa: S110
                target_count = 0
            try:
                scope_size = len(getattr(ctx, "scope_entries", []) or [])
            except Exception:  # noqa: S110
                scope_size = 0
        attributes = {
            "stage_name": stage_name,
            "target_count": int(target_count),
            "scope_size": int(scope_size),
        }
        parent_headers = kwargs.pop("trace_parent_headers", None)
        with self.start_span(
            f"pipeline.stage.{stage_name}", attributes=attributes, parent_headers=parent_headers
        ) as span:
            yield span

    def record_stage_result(self, span: Any, stage_output: Any) -> None:
        state_delta = getattr(stage_output, "state_delta", None)
        if isinstance(state_delta, Mapping):
            span.set_attribute("state_delta.keys", sorted(str(key) for key in state_delta.keys()))
        duration = getattr(stage_output, "duration_seconds", None)
        if duration is not None:
            span.set_attribute("duration_ms", float(duration) * 1000.0)
        outcome = str(getattr(getattr(stage_output, "outcome", ""), "value", "") or "")
        if outcome:
            span.set_attribute("status", "ERROR" if outcome.lower() == "failed" else "OK")
            if outcome.lower() == "failed":
                self._set_error_status(span, getattr(stage_output, "error", "") or "stage failed")
            else:
                self._set_ok_status(span)

    def record_exception(self, span: Any, exc: BaseException) -> None:
        try:
            span.record_exception(exc)
            span.set_attribute("status", "ERROR")
            self._set_error_status(span, str(exc) or exc.__class__.__name__)
        except Exception as e:
            # Fix #338: Log OTel propagation failures instead of silently swallowing
            from src.core.logging.trace_logging import get_pipeline_logger

            get_pipeline_logger(__name__).debug("Failed to record exception in OTel span: %s", e)

    def inject_headers(self, carrier: dict[str, str] | None = None) -> dict[str, str]:
        headers: dict[str, str] = carrier if carrier is not None else {}
        if self.otel_available and self._propagate is not None:
            try:
                self._propagate.inject(headers)
            except Exception:  # noqa: S110
                pass
        return headers

    def inject_task_context(self, envelope: Any) -> Any:
        headers = self.inject_headers({})
        if not headers:
            return envelope
        metadata = dict(getattr(envelope, "metadata", {}) or {})
        metadata["trace_headers"] = headers
        try:
            return replace(
                envelope,
                metadata=metadata,
                traceparent=headers.get("traceparent", envelope.traceparent),
            )
        except Exception:  # noqa: S110
            return envelope

    @staticmethod
    def extract_task_headers(envelope: Any) -> dict[str, str]:
        metadata = dict(getattr(envelope, "metadata", {}) or {})
        raw_headers = metadata.get("trace_headers")
        if isinstance(raw_headers, Mapping):
            return {str(k): str(v) for k, v in raw_headers.items()}
        traceparent = str(getattr(envelope, "traceparent", "") or "")
        return {"traceparent": traceparent} if traceparent else {}

    # Fix #339: Rename config() to get_config() to avoid shadowing built-in meaning
    def get_config(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "status": self.endpoint_status(),
            "otel_available": self.otel_available,
            "local_span_db": str(self.local_exporter.db_path),
            "initialization_error": self.initialization_error,
        }

    def endpoint_status(self) -> str:
        now = time.time()
        if hasattr(self, "_status_cache") and (now - getattr(self, "_status_cache_ts", 0)) < 60.0:
            return self._status_cache

        req = request.Request(str(self.endpoint), method="GET")  # noqa: S310
        try:
            with request.urlopen(req, timeout=1.5):  # noqa: S310
                res = "connected"
        except error.HTTPError:
            res = "connected"
        except Exception:  # noqa: S110
            res = "unreachable"

        self._status_cache = res
        self._status_cache_ts = now
        return res

    def list_traces(
        self,
        *,
        service_name: str | None = None,
        start_ms: int | None = None,
        end_ms: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if service_name:
            where.append("(stage_name = ? OR service_name = ? OR name LIKE ?)")
            params.extend([service_name, service_name, f"%{service_name}%"])
        if start_ms is not None:
            where.append("end_time_unix_nano >= ?")
            params.append(int(start_ms) * 1_000_000)
        if end_ms is not None:
            where.append("start_time_unix_nano <= ?")
            params.append(int(end_ms) * 1_000_000)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        query = """
            WITH filtered AS (
                SELECT trace_id FROM spans {where_sql} GROUP BY trace_id
            ),
            trace_bounds AS (
                SELECT s.trace_id,
                       MIN(s.start_time_unix_nano) AS start_ns,
                       MAX(s.end_time_unix_nano) AS end_ns,
                       SUM(CASE WHEN s.status = 'ERROR' THEN 1 ELSE 0 END) AS error_count,
                       COUNT(*) AS span_count
                FROM spans s
                JOIN filtered f ON f.trace_id = s.trace_id
                GROUP BY s.trace_id
            ),
            roots AS (
                SELECT s.trace_id, s.name, s.stage_name, s.service_name, s.status
                FROM spans s
                JOIN trace_bounds b ON b.trace_id = s.trace_id AND b.start_ns = s.start_time_unix_nano
            )
            SELECT b.trace_id, r.name, r.stage_name, r.service_name, b.start_ns, b.end_ns,
                   ((b.end_ns - b.start_ns) / 1000000.0) AS duration_ms,
                   CASE WHEN b.error_count > 0 THEN 'ERROR' ELSE 'OK' END AS status,
                   b.span_count
            FROM trace_bounds b
            JOIN roots r ON r.trace_id = b.trace_id
            ORDER BY b.start_ns DESC
            LIMIT ?
        """.format(where_sql=where_sql)  # noqa: S608, UP032
        params.append(max(1, min(int(limit), 500)))
        with sqlite3.connect(self.local_exporter.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    def get_trace(self, trace_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.local_exporter.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM spans
                WHERE trace_id = ?
                ORDER BY start_time_unix_nano ASC
                """,
                (trace_id,),
            ).fetchall()
        if not rows:
            return None
        spans = []
        for row in rows:
            item = dict(row)
            item["attributes"] = json.loads(item.pop("attributes_json") or "{}")
            item["events"] = json.loads(item.pop("events_json") or "[]")
            spans.append(item)
        return {"trace_id": trace_id, "spans": spans}

    def _set_ok_status(self, span: Any) -> None:
        if self._status_cls is None or self._status_code_cls is None:
            return
        span.set_status(self._status_cls(self._status_code_cls.OK))

    def _set_error_status(self, span: Any, description: str) -> None:
        if self._status_cls is None or self._status_code_cls is None:
            return
        span.set_status(self._status_cls(self._status_code_cls.ERROR, description))


_MANAGER: TracingManager | None = None
_MANAGER_LOCK = threading.Lock()


def get_tracing_manager() -> TracingManager:
    global _MANAGER
    if _MANAGER is None:
        with _MANAGER_LOCK:
            if _MANAGER is None:
                _MANAGER = TracingManager()
    return _MANAGER


def traced(stage_name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    return get_tracing_manager().traced(stage_name)
