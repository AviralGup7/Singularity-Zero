"""Data models for the scenario execution engine.

Contains dataclasses for step assertions, value extractors, scenario steps,
and execution results.
Extracted from scenario_engine.py for better separation of concerns.
"""

import json
import re
from dataclasses import dataclass, field

from src.core.models import Request, Response


@dataclass(frozen=True)
class StepAssertion:
    expected_statuses: tuple[int, ...] = ()
    expect_success: bool | None = None
    body_contains: tuple[str, ...] = ()
    body_not_contains: tuple[str, ...] = ()
    before_step: str = ""
    after_step: str = ""
    relative_to_step: str = ""
    min_delay_seconds: float | None = None
    max_delay_seconds: float | None = None
    min_latency_seconds: float | None = None
    max_latency_seconds: float | None = None

    def validate(
        self,
        response: Response,
        *,
        step_name: str = "",
        timing: dict[str, dict[str, float]] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        status = int(response.status_code or 0)
        success = status < 400 and not response.error
        if self.expected_statuses and status not in set(self.expected_statuses):
            errors.append(
                f"status {status} not in expected set {sorted(set(self.expected_statuses))}"
            )
        if self.expect_success is True and not success:
            errors.append(f"expected success but received status={status} error={response.error!r}")
        if self.expect_success is False and success:
            errors.append(f"expected failure but received status={status}")
        body = response.body or ""
        for value in self.body_contains:
            if value and value not in body:
                errors.append(f"expected response body to contain {value!r}")
        for value in self.body_not_contains:
            if value and value in body:
                errors.append(f"expected response body to not contain {value!r}")
        latency = float(response.latency_seconds or 0.0)
        if self.min_latency_seconds is not None and latency < float(self.min_latency_seconds):
            errors.append(f"expected latency >= {self.min_latency_seconds} but received {latency}")
        if self.max_latency_seconds is not None and latency > float(self.max_latency_seconds):
            errors.append(f"expected latency <= {self.max_latency_seconds} but received {latency}")
        timeline = timing or {}
        current = timeline.get(step_name, {})
        current_start = float(current.get("started_at", 0.0) or 0.0)
        current_end = float(current.get("completed_at", current_start) or current_start)
        if self.before_step:
            before = timeline.get(self.before_step, {})
            before_start = float(before.get("started_at", 0.0) or 0.0)
            if before and before_start and current_end > before_start:
                errors.append(
                    f"expected step {step_name!r} to complete before {self.before_step!r}"
                )
        if self.after_step:
            after = timeline.get(self.after_step, {})
            after_end = float(after.get("completed_at", 0.0) or 0.0)
            if after and after_end and current_start < after_end:
                errors.append(f"expected step {step_name!r} to start after {self.after_step!r}")
        if self.relative_to_step and (
            self.min_delay_seconds is not None or self.max_delay_seconds is not None
        ):
            anchor = timeline.get(self.relative_to_step, {})
            anchor_end = float(anchor.get("completed_at", 0.0) or 0.0)
            if anchor and anchor_end:
                delta = current_start - anchor_end
                if self.min_delay_seconds is not None and delta < float(self.min_delay_seconds):
                    errors.append(
                        f"expected start delay from {self.relative_to_step!r} >= {self.min_delay_seconds} but received {round(delta, 3)}"
                    )
                if self.max_delay_seconds is not None and delta > float(self.max_delay_seconds):
                    errors.append(
                        f"expected start delay from {self.relative_to_step!r} <= {self.max_delay_seconds} but received {round(delta, 3)}"
                    )
        return errors


@dataclass(frozen=True)
class ValueExtractor:
    name: str
    source: str = "body"
    pattern: str = ""
    header: str = ""
    json_path: str = ""
    group: int = 1

    def extract(self, response: Response) -> str | None:
        source = self.source.strip().lower()
        if source == "header":
            if not self.header:
                return None
            header_name = self.header.strip().lower()
            for key, value in response.headers.items():
                if str(key).strip().lower() == header_name:
                    return str(value)
            return None
        if source == "json":
            if not self.json_path:
                return None
            try:
                payload = json.loads(response.body or "")
            except Exception:  # noqa: BLE001
                return None
            value = payload
            for segment in self.json_path.split("."):
                token = segment.strip()
                if not token:
                    continue
                if not isinstance(value, dict) or token not in value:
                    return None
                value = value[token]
            if value is None:
                return None
            return str(value)
        if not self.pattern:
            return None
        match = re.search(self.pattern, response.body or "")
        if not match:
            return None
        try:
            return str(match.group(self.group))
        except IndexError:
            return None


@dataclass(frozen=True)
class ScenarioStep:
    name: str
    request: Request
    extractors: tuple[ValueExtractor, ...] = ()
    assertions: tuple[StepAssertion, ...] = ()
    session_key: str = ""
    actor: str = ""
    parallel_group: str = ""
    wait_for_steps: tuple[str, ...] = ()
    wait_for_barriers: tuple[str, ...] = ()
    publish_barrier: str = ""
    when: str = ""


@dataclass(frozen=True)
class ScenarioStepResult:
    name: str
    request: Request
    response: Response
    extracted_values: dict[str, str] = field(default_factory=dict)
    assertion_errors: tuple[str, ...] = ()
    actor: str = ""
    session_key: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    skipped: bool = False

    @property
    def passed(self) -> bool:
        return not self.assertion_errors


@dataclass(frozen=True)
class ScenarioRunResult:
    steps: tuple[ScenarioStepResult, ...]
    variables: dict[str, str]
    active_session: str

    @property
    def success(self) -> bool:
        return all(step.passed for step in self.steps)
