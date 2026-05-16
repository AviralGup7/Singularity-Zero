"""Structured logging system for the cyber security test pipeline.

Provides JSON-formatted log entries with consistent schema, contextual fields,
log correlation across services, sensitive data redaction, async log handlers,
log rotation, and pre-configured loggers for each pipeline package.

Usage:
    from src.infrastructure.observability.structured_logging import get_logger, setup_logging

    setup_logging()
    logger = get_logger("queue_system")
    logger.info("Job enqueued", job_id="abc123", target="example.com")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from logging.handlers import QueueListener, RotatingFileHandler
from queue import SimpleQueue
from typing import Any

from src.infrastructure.observability.config import get_config

_trace_id: ContextVar[str | None] = ContextVar("trace_id", default=None)
_span_id: ContextVar[str | None] = ContextVar("span_id", default=None)
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_job_id: ContextVar[str | None] = ContextVar("job_id", default=None)
_user_id: ContextVar[str | None] = ContextVar("user_id", default=None)

SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    "api_key": re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-._~+/]+=*)"),
    "password": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]+)"),
    "secret": re.compile(r"(?:secret|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9\-._~+/]+=*)"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

REDACTED_VALUE = "[REDACTED]"
EMAIL_REDACTED = "***@***.***"
IP_REDACTED = "***.***.***.***"


def get_trace_id() -> str | None:
    """Get the current trace ID from context."""
    return _trace_id.get()


def set_trace_id(trace_id: str | None) -> None:
    """Set the trace ID in the current context.

    Args:
        trace_id: The trace ID to set, or None to clear.
    """
    _trace_id.set(trace_id)


def get_span_id() -> str | None:
    """Get the current span ID from context."""
    return _span_id.get()


def set_span_id(span_id: str | None) -> None:
    """Set the span ID in the current context.

    Args:
        span_id: The span ID to set, or None to clear.
    """
    _span_id.set(span_id)


def get_request_id() -> str | None:
    """Get the current request ID from context."""
    return _request_id.get()


def set_request_id(request_id: str | None) -> None:
    """Set the request ID in the current context.

    Args:
        request_id: The request ID to set, or None to clear.
    """
    _request_id.set(request_id)


def get_job_id() -> str | None:
    """Get the current job ID from context."""
    return _job_id.get()


def set_job_id(job_id: str | None) -> None:
    """Set the job ID in the current context.

    Args:
        job_id: The job ID to set, or None to clear.
    """
    _job_id.set(job_id)


def get_user_id() -> str | None:
    """Get the current user ID from context."""
    return _user_id.get()


def set_user_id(user_id: str | None) -> None:
    """Set the user ID in the current context.

    Args:
        user_id: The user ID to set, or None to clear.
    """
    _user_id.set(user_id)


def generate_correlation_id() -> str:
    """Generate a new unique correlation ID.

    Returns:
        A UUID4-based correlation ID string.
    """
    return uuid.uuid4().hex[:16]


def redact_sensitive_data(data: Any, sensitive_fields: list[str] | None = None) -> Any:
    """Recursively redact sensitive data from a value.

    Scans dictionaries for sensitive keys and strings for sensitive patterns,
    replacing them with redacted placeholders.

    Args:
        data: The data to redact. Can be any type.
        sensitive_fields: List of field names to redact. Uses defaults if None.

    Returns:
        The data with sensitive values replaced by redaction markers.
    """
    config = get_config()
    fields = sensitive_fields or config.logging.sensitive_fields
    fields_lower = [f.lower() for f in fields]

    if isinstance(data, dict):
        return {
            k: REDACTED_VALUE if k.lower() in fields_lower else redact_sensitive_data(v, fields)
            for k, v in data.items()
        }
    if isinstance(data, (list, tuple)):
        return type(data)(redact_sensitive_data(item, fields) for item in data)
    if isinstance(data, str):
        return _redact_string_patterns(data)
    return data


def _redact_string_patterns(text: str) -> str:
    """Redact sensitive patterns from a string.

    Args:
        text: The string to scan and redact.

    Returns:
        The string with sensitive patterns replaced.
    """
    result = text
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        if pattern_name == "email":
            result = pattern.sub(EMAIL_REDACTED, result)
        elif pattern_name == "ipv4":
            result = pattern.sub(IP_REDACTED, result)
        else:
            result = pattern.sub(REDACTED_VALUE, result)
    return result


class JSONFormatter(logging.Formatter):
    """JSON log formatter with consistent schema and contextual fields.

    Produces log entries with the following schema:
        {
            "timestamp": "ISO 8601 timestamp",
            "level": "LOG_LEVEL",
            "message": "Log message",
            "service": "Service name",
            "logger": "Logger name",
            "trace_id": "Trace correlation ID",
            "span_id": "Span ID",
            "request_id": "Request correlation ID",
            "job_id": "Job ID",
            "user_id": "User ID",
            "stage": "Pipeline stage",
            "target": "Scan target",
            "duration_ms": "Operation duration in milliseconds",
            "extra": { ... additional fields ... },
            "source": { "file": "...", "line": 0, "function": "..." }
        }
    """

    def __init__(
        self,
        service_name: str = "cyber-security-pipeline",
        include_source: bool = False,
        sensitive_fields: list[str] | None = None,
    ) -> None:
        """Initialize the JSON formatter.

        Args:
            service_name: Name of the service for log identification.
            include_source: Whether to include source file/line/function.
            sensitive_fields: Field names to redact in output.
        """
        super().__init__()
        self.service_name = service_name
        self.include_source = include_source
        self.sensitive_fields = sensitive_fields or []

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string.

        Args:
            record: The log record to format.

        Returns:
            JSON-formatted log entry string.
        """
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "service": self.service_name,
            "logger": record.name,
        }

        trace_id = _trace_id.get()
        if trace_id:
            entry["trace_id"] = trace_id

        span_id = _span_id.get()
        if span_id:
            entry["span_id"] = span_id

        request_id = _request_id.get()
        if request_id:
            entry["request_id"] = request_id

        job_id = _job_id.get()
        if job_id:
            entry["job_id"] = job_id

        user_id = _user_id.get()
        if user_id:
            entry["user_id"] = user_id

        extra_fields: dict[str, Any] = {}
        for key in ("stage", "target", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                extra_fields[key] = value

        skip_keys = {
            "name",
            "msg",
            "args",
            "created",
            "relativeCreated",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "pathname",
            "filename",
            "module",
            "msecs",
            "levelno",
            "levelname",
            "process",
            "processName",
            "thread",
            "threadName",
            "taskName",
            "message",
        }
        for key, value in record.__dict__.items():
            if key not in skip_keys:
                extra_fields[key] = value

        if extra_fields:
            entry["extra"] = redact_sensitive_data(extra_fields, self.sensitive_fields)

        if self.include_source:
            entry["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        return json.dumps(entry, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatter with color support."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET": "\033[0m",
    }

    def __init__(self, service_name: str = "cyber-security-pipeline") -> None:
        """Initialize the console formatter.

        Args:
            service_name: Service name prefix for log entries.
        """
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record for console output.

        Args:
            record: The log record to format.

        Returns:
            Formatted log string with optional color codes.
        """
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[
            :-3
        ]
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]

        parts = [
            f"[{timestamp}]",
            f"{color}{record.levelname:<8}{reset}",
            f"{self.service_name}:{record.name}",
            "-",
            record.getMessage(),
        ]

        extra_parts = []
        for key in ("stage", "target", "job_id", "trace_id", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                extra_parts.append(f"{key}={value}")

        if extra_parts:
            parts.append("{" + ", ".join(extra_parts) + "}")

        if record.exc_info and record.exc_info[0] is not None:
            parts.append(self.formatException(record.exc_info))

        return " ".join(parts)


class AsyncLogHandler(logging.Handler):
    """Async-compatible log handler using a background thread.

    Wraps a QueueHandler/QueueListener pair to provide non-blocking
    log I/O. Log records are enqueued immediately and written by a
    dedicated background thread.
    """

    def __init__(
        self,
        wrapped_handler: logging.Handler,
        max_queue_size: int = 10000,
    ) -> None:
        """Initialize the async log handler.

        Args:
            wrapped_handler: The underlying handler to delegate to.
            max_queue_size: Maximum number of log records to queue.
        """
        super().__init__()
        """Initialize the async log handler.

        Args:
            wrapped_handler: The underlying handler to delegate to.
            max_queue_size: Maximum number of log records to queue.
        """
        self._queue: SimpleQueue[logging.LogRecord] = SimpleQueue()
        self._wrapped = wrapped_handler
        self._listener: QueueListener | None = None
        self._max_queue_size = max_queue_size
        self._started = False

    def start(self) -> None:
        """Start the background log processing thread."""
        if self._started:
            return
        self._listener = QueueListener(
            self._queue,
            self._wrapped,
            respect_handler_level=True,
        )
        self._listener.start()
        self._started = True

    def stop(self) -> None:
        """Stop the background thread and flush pending logs."""
        if self._listener is not None:
            self._listener.stop()
            self._listener = None
        self._started = False

    def emit(self, record: logging.LogRecord) -> None:
        """Enqueue a log record for async processing.

        Args:
            record: The log record to enqueue.
        """
        if not self._started:
            self._wrapped.handle(record)
            return
        try:
            self._queue.put_nowait(record)
        except Exception:
            self._wrapped.handle(record)

    def __enter__(self) -> AsyncLogHandler:
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.stop()


class PipelineLogger:
    """Enhanced logger with pipeline-specific context methods.

    Provides convenience methods that automatically populate
    pipeline-specific fields (stage, target, duration_ms) and
    support structured extra fields.
    """

    def __init__(self, name: str) -> None:
        """Initialize the pipeline logger.

        Args:
            name: Logger name, typically the module/package name.
        """
        self._logger = logging.getLogger(name)
        self._name = name

    @property
    def name(self) -> str:
        """Get the logger name."""
        return self._name

    @property
    def logger(self) -> logging.Logger:
        """Get the underlying Python logger."""
        return self._logger

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log a DEBUG message with optional structured fields."""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log an INFO message with optional structured fields."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log a WARNING message with optional structured fields."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log an ERROR message with optional structured fields."""
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log a CRITICAL message with optional structured fields."""
        self._log(logging.CRITICAL, message, **kwargs)

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log an ERROR message with exception info."""
        self._log(logging.ERROR, message, exc_info=True, **kwargs)

    def _log(self, level: int, message: str, **kwargs: Any) -> None:
        """Internal log method that injects structured fields."""
        extra: dict[str, Any] = {}
        for key in ("stage", "target", "duration_ms", "job_id", "request_id", "user_id"):
            value = kwargs.pop(key, None)
            if value is not None:
                extra[key] = value

        if kwargs:
            extra["fields"] = kwargs

        self._logger.log(level, message, extra=extra)

    def timed(self, operation: str, **context: Any) -> TimedLogContext:
        """Create a timed logging context manager.

        Automatically logs the operation start and completion with
        the elapsed duration in milliseconds.

        Example:
            with logger.timed("scan", target="example.com"):
                perform_scan()
        """
        return TimedLogContext(self, operation, **context)


class TimedLogContext:
    """Context manager for timed operations with automatic logging."""

    def __init__(self, logger: PipelineLogger, operation: str, **context: Any) -> None:
        """Initialize the timed context.

        Args:
            logger: The PipelineLogger to use for output.
            operation: Name of the operation being timed.
            **context: Additional context fields.
        """
        self._logger = logger
        self._operation = operation
        self._context = context
        self._start_time = 0.0

    def __enter__(self) -> TimedLogContext:
        """Enter the timed context. Logs operation start."""
        self._start_time = time.monotonic()
        self._logger.info(f"Starting {self._operation}", **self._context)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the timed context. Logs completion with duration or error."""
        duration_ms = (time.monotonic() - self._start_time) * 1000
        context = {**self._context, "duration_ms": round(duration_ms, 2)}

        if exc_val is not None:
            self._logger.error(
                f"Failed {self._operation} after {duration_ms:.1f}ms",
                error=str(exc_val),
                **context,
            )
        else:
            self._logger.info(
                f"Completed {self._operation} in {duration_ms:.1f}ms",
                **context,
            )


_package_loggers: dict[str, PipelineLogger] = {}

_pre_configured_packages = [
    "queue_system",
    "execution_engine",
    "cache_layer",
    "fastapi_dashboard",
    "websocket_server",
    "optimized_stages",
    "observability",
    "core",
    "pipeline_platform",
    "dashboard_app",
    "recon",
    "analysis",
    "detection",
    "decision",
    "fuzzing",
    "reporting",
    "intelligence",
]


def setup_logging(
    config: Any = None,
    loggers: list[str] | None = None,
) -> None:
    """Configure the logging system with structured JSON output.

    Sets up handlers, formatters, and log levels for all specified
    package loggers. Uses async handlers when enabled in config.

    Args:
        config: ObservabilityConfig instance. Uses global config if None.
        loggers: List of logger names to configure. Configures all known
            package loggers if None.
    """
    if config is None:
        config = get_config()

    log_config = config.logging
    targets = loggers or _pre_configured_packages

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_config.level.value))
    root_logger.handlers.clear()

    if log_config.format == "json":
        formatter: logging.Formatter = JSONFormatter(
            service_name=log_config.service_name,
            include_source=log_config.include_source,
            sensitive_fields=log_config.sensitive_fields,
        )
    else:
        formatter = ConsoleFormatter(service_name=log_config.service_name)

    if log_config.output_path:
        log_dir = os.path.dirname(os.path.abspath(log_config.output_path))
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_config.output_path,
            maxBytes=log_config.max_file_size_mb * 1024 * 1024,
            backupCount=log_config.backup_count,
        )
        file_handler.setFormatter(formatter)
        handler: logging.Handler = file_handler
    else:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        handler = stream_handler

    if log_config.enable_async:
        async_handler = AsyncLogHandler(handler)
        async_handler.start()
        root_logger.addHandler(async_handler)
    else:
        root_logger.addHandler(handler)

    for pkg in targets:
        pkg_logger = logging.getLogger(pkg)
        pkg_logger.setLevel(getattr(logging, log_config.level.value))
        pkg_logger.propagate = True

    for pkg in targets:
        _package_loggers[pkg] = PipelineLogger(pkg)


def get_logger(name: str) -> PipelineLogger:
    """Get or create a PipelineLogger for the given name.

    If setup_logging() has been called, returns the pre-configured
    logger. Otherwise creates a new PipelineLogger on demand.

    Args:
        name: Logger name, typically a module or package name.

    Returns:
        A PipelineLogger instance for the given name.
    """
    if name in _package_loggers:
        return _package_loggers[name]

    logger = PipelineLogger(name)
    _package_loggers[name] = logger
    return logger


def inject_context(
    trace_id: str | None = None,
    span_id: str | None = None,
    request_id: str | None = None,
    job_id: str | None = None,
    user_id: str | None = None,
) -> Callable[..., Any]:
    """Create a decorator that injects correlation context into the wrapped function.

    Sets the specified correlation IDs in context variables before
    executing the wrapped function, enabling log correlation across
    async call chains.

    Args:
        trace_id: Trace ID to inject.
        span_id: Span ID to inject.
        request_id: Request ID to inject.
        job_id: Job ID to inject.
        user_id: User ID to inject.

    Returns:
        A decorator that injects context into the wrapped function.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        import functools

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            tokens: list[tuple[ContextVar[Any], Any]] = []
            if trace_id is not None:
                tokens.append((_trace_id, _trace_id.set(trace_id)))
            if span_id is not None:
                tokens.append((_span_id, _span_id.set(span_id)))
            if request_id is not None:
                tokens.append((_request_id, _request_id.set(request_id)))
            if job_id is not None:
                tokens.append((_job_id, _job_id.set(job_id)))
            if user_id is not None:
                tokens.append((_user_id, _user_id.set(user_id)))
            try:
                return await func(*args, **kwargs)
            finally:
                for var, token in tokens:
                    var.reset(token)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            tokens: list[tuple[ContextVar[Any], Any]] = []
            if trace_id is not None:
                tokens.append((_trace_id, _trace_id.set(trace_id)))
            if span_id is not None:
                tokens.append((_span_id, _span_id.set(span_id)))
            if request_id is not None:
                tokens.append((_request_id, _request_id.set(request_id)))
            if job_id is not None:
                tokens.append((_job_id, _job_id.set(job_id)))
            if user_id is not None:
                tokens.append((_user_id, _user_id.set(user_id)))
            try:
                return func(*args, **kwargs)
            finally:
                for var, token in tokens:
                    var.reset(token)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
