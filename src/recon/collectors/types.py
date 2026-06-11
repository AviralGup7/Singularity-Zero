"""Typed metadata contracts shared by all in-house collectors and source wrappers.

Historically each provider returned a free-form ``dict[str, Any]`` for
its per-run metadata.  Keys were inconsistent (``errors`` was missing
from the crawler, ``hosts_scanned`` only appeared on archive providers,
``duration_seconds`` was sometimes rounded and sometimes not).  The
ad-hoc shape made :func:`src.recon.collectors.aggregator.metrics_summary`
brittle and prevented type-checking from catching real bugs.

This module defines :class:`CollectorMeta`, a frozen dataclass with a
fixed set of typed fields that every provider, aggregator, and source
wrapper now produces.  For backwards compatibility the class also
implements a small dict-like surface (``.get``, ``__getitem__``,
``__contains__``, ``items``, ``keys``) so any caller that still treats
metadata as a plain dictionary continues to work without modification.

A :class:`CollectorStatus` string-enum constrains the legal values of
the ``status`` field; the enum subclasses ``str`` so equality against
the literal status strings used throughout the codebase still works.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import Any, ItemsView, KeysView, ValuesView


class CollectorStatus(StrEnum):
    """Canonical status values reported by collectors and source wrappers.

    Subclassing ``str`` means an enum value compares equal to its
    underlying string, so callers that still use bare strings continue
    to work::

        meta.status == "ok"           # True
        meta.status == CollectorStatus.OK  # True
    """

    OK = "ok"
    EMPTY = "empty"
    ERROR = "error"
    SKIPPED = "skipped"
    SKIPPED_LARGE_TARGET = "skipped_large_target"
    SKIPPED_CIRCUIT_OPEN = "skipped_circuit_open"
    TIMEOUT = "timeout"
    PARTIAL = "partial"
    AUTH_FAILED = "auth_failed"
    RATE_LIMITED = "rate_limited"
    PENDING = "pending"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CollectorMeta:
    """Typed metadata reported by a single collector / source run.

    Attributes:
        status: One of :class:`CollectorStatus`. ``"ok"`` when at least
            one URL was returned, ``"empty"`` for a successful run with
            zero results, ``"error"`` for any caught exception, and
            ``"timeout"`` / ``"skipped_circuit_open"`` for the new
            aggregator-level guards introduced in this refactor.
        duration_seconds: Wall-clock time, in seconds, the call took.
            Rounded to one decimal in producer code for readability.
        new_urls: Number of distinct items the collector returned.
        errors: Number of per-host (or per-page) errors encountered.
            Always present; defaults to 0 for providers that previously
            omitted the field.
        hosts_scanned: Number of distinct hosts the collector queried.
            ``None`` when the concept does not apply (e.g. a
            domain-level subdomain source).
        timeout_count: Number of per-host requests that hit the
            configured timeout. ``0`` by default.
        provider_name: Short identifier of the provider that produced
            the result (e.g. ``"wayback"``). Mirrors the ``name`` key
            used by ``select_enabled_providers``.
        warnings: Optional human-readable warnings the provider wants
            to surface (rate limits hit, auth degraded, partial result).
        extras: Provider-specific extension fields. Always a fresh
            dict; consumers must not rely on any particular key. New
            telemetry should prefer dedicated typed fields over
            stuffing into ``extras``.
    """

    status: CollectorStatus = CollectorStatus.UNKNOWN
    duration_seconds: float = 0.0
    new_urls: int = 0
    errors: int = 0
    hosts_scanned: int | None = None
    timeout_count: int = 0
    provider_name: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)
    extras: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Dict-compatibility shim
    # ------------------------------------------------------------------
    # The historical contract was ``dict[str, Any]`` and many consumers
    # (notably ``aggregator.metrics_summary`` and downstream report
    # generators) still call ``meta.get(...)`` or ``meta["..."]``.  We
    # expose those operations against the typed fields plus the
    # ``extras`` dict so the migration is fully backwards compatible.

    def _as_dict(self) -> dict[str, Any]:
        base: dict[str, Any] = {
            "status": self.status.value
            if isinstance(self.status, CollectorStatus)
            else str(self.status),
            "duration_seconds": float(self.duration_seconds),
            "new_urls": int(self.new_urls),
            "errors": int(self.errors),
            "timeout_count": int(self.timeout_count),
            "provider_name": str(self.provider_name),
            "warnings": list(self.warnings),
        }
        if self.hosts_scanned is not None:
            base["hosts_scanned"] = int(self.hosts_scanned)
        if self.extras:
            for key, value in self.extras.items():
                # Never let extras overwrite the typed fields.
                base.setdefault(key, value)
        return base

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the metadata."""
        return self._as_dict()

    def get(self, key: str, default: Any = None) -> Any:
        return self._as_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        try:
            return self._as_dict()[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def __contains__(self, key: object) -> bool:
        return key in self._as_dict()

    def __iter__(self) -> Iterator[str]:
        return iter(self._as_dict())

    def items(self) -> ItemsView[str, Any]:
        return self._as_dict().items()

    def keys(self) -> KeysView[str]:
        return self._as_dict().keys()

    def values(self) -> ValuesView[Any]:
        return self._as_dict().values()

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def with_updates(self, **changes: Any) -> CollectorMeta:
        """Return a new instance with the given fields overridden.

        Convenience wrapper around :func:`dataclasses.replace` that
        coerces the ``status`` argument to :class:`CollectorStatus` so
        callers can pass either the enum or a bare string.
        """
        if "status" in changes and not isinstance(changes["status"], CollectorStatus):
            try:
                changes["status"] = CollectorStatus(changes["status"])
            except ValueError:
                changes["status"] = CollectorStatus.UNKNOWN
        return replace(self, **changes)

    def is_successful(self) -> bool:
        """Return True when the run produced data without erroring out."""
        return self.status in (CollectorStatus.OK, CollectorStatus.PARTIAL)

    def is_failure(self) -> bool:
        return self.status in (
            CollectorStatus.ERROR,
            CollectorStatus.TIMEOUT,
            CollectorStatus.AUTH_FAILED,
        )

    @classmethod
    def coerce(
        cls,
        value: Any,
        *,
        provider_name: str | None = None,
        default_status: CollectorStatus = CollectorStatus.UNKNOWN,
    ) -> CollectorMeta:
        """Coerce ``value`` into a :class:`CollectorMeta` (see :func:`coerce_meta`)."""
        return coerce_meta(
            value,
            provider_name=provider_name,
            default_status=default_status,
        )


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------


def coerce_meta(
    value: Any,
    *,
    provider_name: str | None = None,
    default_status: CollectorStatus = CollectorStatus.UNKNOWN,
) -> CollectorMeta:
    """Coerce ``value`` into a :class:`CollectorMeta` instance.

    Accepts:
        * An existing :class:`CollectorMeta` (returned as-is, with the
          provider name backfilled if missing).
        * A :class:`Mapping` (the historical contract) which is mapped
          field-by-field, with unknown keys preserved under ``extras``.
        * ``None`` (returns an empty meta with ``default_status``).

    This function is the single conversion point used by the streaming
    aggregator and meta-wrappers when adapting legacy provider output
    to the typed contract.
    """
    if isinstance(value, CollectorMeta):
        if provider_name and not value.provider_name:
            return value.with_updates(provider_name=provider_name)
        return value

    if value is None:
        return CollectorMeta(
            status=default_status,
            provider_name=provider_name or "",
        )

    if not isinstance(value, Mapping):
        return CollectorMeta(
            status=CollectorStatus.UNKNOWN,
            provider_name=provider_name or "",
            extras={"raw": value},
        )

    typed_fields = {
        "status",
        "duration_seconds",
        "new_urls",
        "errors",
        "hosts_scanned",
        "timeout_count",
        "provider_name",
        "warnings",
    }
    extras: dict[str, Any] = {}
    kwargs: dict[str, Any] = {}
    for key, val in value.items():
        if key in typed_fields:
            kwargs[key] = val
        else:
            extras[key] = val

    # Normalise + sanity-check typed values.
    if "status" in kwargs:
        try:
            kwargs["status"] = CollectorStatus(kwargs["status"])
        except (ValueError, TypeError):
            kwargs["status"] = default_status
    else:
        kwargs["status"] = default_status

    if "duration_seconds" in kwargs:
        try:
            kwargs["duration_seconds"] = float(kwargs["duration_seconds"])
        except (TypeError, ValueError):
            kwargs["duration_seconds"] = 0.0

    for int_field in ("new_urls", "errors", "timeout_count"):
        if int_field in kwargs:
            try:
                kwargs[int_field] = int(kwargs[int_field])
            except (TypeError, ValueError):
                kwargs[int_field] = 0

    if "hosts_scanned" in kwargs and kwargs["hosts_scanned"] is not None:
        try:
            kwargs["hosts_scanned"] = int(kwargs["hosts_scanned"])
        except (TypeError, ValueError):
            kwargs["hosts_scanned"] = None

    if "warnings" in kwargs:
        raw_warnings = kwargs["warnings"]
        if isinstance(raw_warnings, str):
            kwargs["warnings"] = (raw_warnings,)
        elif raw_warnings is None:
            kwargs["warnings"] = ()
        else:
            try:
                kwargs["warnings"] = tuple(str(w) for w in raw_warnings)
            except TypeError:
                kwargs["warnings"] = ()

    if provider_name and not kwargs.get("provider_name"):
        kwargs["provider_name"] = provider_name

    return CollectorMeta(extras=extras, **kwargs)


def merge_meta(*metas: CollectorMeta) -> CollectorMeta:
    """Combine several :class:`CollectorMeta` runs into a single summary.

    Used by the streaming aggregator and the meta-wrappers when several
    underlying calls (per-host iterations, paginated API hits) feed
    into a single logical stage.
    """
    if not metas:
        return CollectorMeta()
    statuses: list[CollectorStatus] = []
    total_urls = 0
    total_errors = 0
    total_duration = 0.0
    total_timeouts = 0
    scanned: int = 0
    saw_scanned = False
    warnings: list[str] = []
    extras: dict[str, Any] = {}
    provider_name = ""
    for meta in metas:
        statuses.append(meta.status)
        total_urls += int(meta.new_urls)
        total_errors += int(meta.errors)
        total_duration += float(meta.duration_seconds)
        total_timeouts += int(meta.timeout_count)
        if meta.hosts_scanned is not None:
            saw_scanned = True
            scanned += int(meta.hosts_scanned)
        warnings.extend(meta.warnings)
        for k, v in meta.extras.items():
            extras.setdefault(k, v)
        if meta.provider_name and not provider_name:
            provider_name = meta.provider_name

    if any(s == CollectorStatus.OK for s in statuses):
        merged_status = CollectorStatus.OK
    elif any(s == CollectorStatus.PARTIAL for s in statuses):
        merged_status = CollectorStatus.PARTIAL
    elif all(s == CollectorStatus.EMPTY for s in statuses):
        merged_status = CollectorStatus.EMPTY
    elif any(s == CollectorStatus.TIMEOUT for s in statuses):
        merged_status = CollectorStatus.TIMEOUT
    elif any(s == CollectorStatus.ERROR for s in statuses):
        merged_status = CollectorStatus.ERROR
    else:
        merged_status = statuses[0] if statuses else CollectorStatus.UNKNOWN

    return CollectorMeta(
        status=merged_status,
        duration_seconds=round(total_duration, 1),
        new_urls=total_urls,
        errors=total_errors,
        hosts_scanned=scanned if saw_scanned else None,
        timeout_count=total_timeouts,
        provider_name=provider_name,
        warnings=tuple(dict.fromkeys(warnings)),  # dedupe, preserve order
        extras=extras,
    )


__all__ = [
    "CollectorMeta",
    "CollectorStatus",
    "coerce_meta",
    "merge_meta",
    "asdict",  # re-export for convenience
]
