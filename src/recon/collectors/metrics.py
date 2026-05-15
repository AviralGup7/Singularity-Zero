from __future__ import annotations

"""Prometheus metrics for the recon collectors.

Provides simple helper functions to increment provider-level counters
and observe durations. If `prometheus_client` is not installed, this
module falls back to lightweight no-op implementations so unit tests
and environments without Prometheus can import the package.
"""
try:
    from prometheus_client import Counter, Histogram  # type: ignore

    _PROVIDER_REQUESTS = Counter(
        "recon_provider_requests_total",
        "Total requests made to a provider",
        ["provider"],
    )

    _PROVIDER_ERRORS = Counter(
        "recon_provider_errors_total",
        "Total errors encountered by a provider",
        ["provider"],
    )

    _PROVIDER_URLS = Counter(
        "recon_provider_urls_total",
        "Number of URLs emitted by a provider",
        ["provider"],
    )

    _PROVIDER_DURATION = Histogram(
        "recon_provider_duration_seconds",
        "Duration in seconds of provider collection calls",
        ["provider"],
    )

    def increment_requests(provider: str, n: int = 1) -> None:
        _PROVIDER_REQUESTS.labels(provider=provider).inc(n)

    def increment_errors(provider: str, n: int = 1) -> None:
        _PROVIDER_ERRORS.labels(provider=provider).inc(n)

    def increment_urls(provider: str, n: int = 1) -> None:
        _PROVIDER_URLS.labels(provider=provider).inc(n)

    def observe_duration(provider: str, seconds: float) -> None:
        _PROVIDER_DURATION.labels(provider=provider).observe(seconds)

except Exception:  # pragma: no cover - fallback in environments without prometheus

    class _NoopMetric:
        def labels(self, **_: dict) -> _NoopMetric:
            return self

        def inc(self, _=1) -> None:  # type: ignore[override]
            return None

        def observe(self, _=0.0) -> None:  # type: ignore[override]
            return None

    _PROVIDER_REQUESTS = _NoopMetric()
    _PROVIDER_ERRORS = _NoopMetric()
    _PROVIDER_URLS = _NoopMetric()
    _PROVIDER_DURATION = _NoopMetric()

    def increment_requests(provider: str, n: int = 1) -> None:  # type: ignore[override]
        return None

    def increment_errors(provider: str, n: int = 1) -> None:  # type: ignore[override]
        return None

    def increment_urls(provider: str, n: int = 1) -> None:  # type: ignore[override]
        return None

    def observe_duration(provider: str, seconds: float) -> None:  # type: ignore[override]
        return None


__all__ = [
    "increment_requests",
    "increment_errors",
    "increment_urls",
    "observe_duration",
]
