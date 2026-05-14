from dataclasses import dataclass


@dataclass(frozen=True)
class ApiTestContext:
    title: str
    severity: str
    confidence: str
    method: str
    url: str
    baseline_url: str
    path: str
    query: str
    baseline_path: str
    baseline_query: str
    parameter: str
    variant: str
    replay_id: str
    combined_signal: str
    next_step: str


@dataclass(frozen=True)
class RequestSummary:
    ok: bool
    error: str
    status_code: int | None
    content_type: str
    body_length: int


@dataclass(frozen=True)
class ComparisonSummary:
    status_changed: bool
    length_changed: bool
    interesting_difference: bool
