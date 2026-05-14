from dataclasses import dataclass, field
from typing import Any, Literal

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
SeverityLevel = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str | bytes | None = None
    timeout_seconds: int | None = None


@dataclass(frozen=True)
class Response:
    requested_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    latency_seconds: float = 0.0
    error: str = ""


@dataclass(frozen=True)
class Finding:
    category: str
    title: str
    url: str
    severity: SeverityLevel
    confidence: float
    score: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    signals: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_LEVELS:
            valid = ", ".join(SEVERITY_LEVELS)
            msg = f"severity must be one of ({valid}), got {self.severity!r}"
            raise ValueError(msg)


@dataclass(frozen=True)
class ValidationResult:
    validator: str
    category: str
    status: str
    url: str
    confidence: float
    in_scope: bool
    scope_reason: str
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] = field(default_factory=dict)
    validation_actions: list[dict[str, Any]] = field(default_factory=list)
