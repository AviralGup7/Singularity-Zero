from __future__ import annotations

import re
from dataclasses import dataclass, field

_TRACEBACK_PREFIXES = (
    "traceback (most recent call last):",
    "timeouterror exception in shielded future",
)
_TRACEBACK_FRAME_PREFIXES = ('file "',)
_FATAL_PREFIXES = (
    "error:",
    "fatal:",
    "critical:",
)
_FATAL_MARKERS = (
    "critical recon stage failed",
    "pipeline failed",
    "unhandled exception",
    "uncaught exception",
)
_BUDGET_MARKERS = (
    "runtime budget",
    "budget exceeded",
    "budget reached",
    "clamping",
)
_CLEANUP_TIMEOUT_MARKERS = (
    "exception in shielded future",
    "synchronous operation exceeded",
)
_KNOWN_PROVIDERS = (
    "gau",
    "waybackurls",
    "katana",
    "httpx",
    "subfinder",
    "assetfinder",
    "amass",
    "nuclei",
)
_PYTHON_WARNING_RE = re.compile(r"^.+:\d+:\s+[A-Za-z_][\w.]*Warning:\s+.+")
_WARNING_CONTEXT_PREFIXES = ("warnings.warn(",)


@dataclass(slots=True)
class StderrClassification:
    warnings: list[str] = field(default_factory=list)
    retry_warnings: list[str] = field(default_factory=list)
    budget_clamped_timeouts: list[str] = field(default_factory=list)
    tracebacks: list[str] = field(default_factory=list)
    fatal_signal_lines: list[str] = field(default_factory=list)
    cleanup_timeout_tracebacks: list[str] = field(default_factory=list)
    other_lines: list[str] = field(default_factory=list)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    @property
    def fatal_traceback_lines(self) -> list[str]:
        if self.cleanup_timeout_tracebacks and not self.fatal_signal_lines:
            return []
        return list(self.tracebacks)

    @property
    def fatal_signal_count(self) -> int:
        return len(self.fatal_signal_lines) + len(self.fatal_traceback_lines)

    @property
    def has_fatal_signals(self) -> bool:
        return self.fatal_signal_count > 0

    @property
    def timeout_events(self) -> list[str]:
        events = list(self.budget_clamped_timeouts)
        for line in self.warnings:
            lowered = line.lower()
            if "timed out" in lowered and line not in events:
                events.append(line)
        for line in self.cleanup_timeout_tracebacks:
            lowered = line.lower()
            if "timeout" in lowered and line not in events:
                events.append(line)
        return events

    @property
    def nonfatal_lines(self) -> list[str]:
        lines = [
            *self.warnings,
            *self.budget_clamped_timeouts,
            *self.cleanup_timeout_tracebacks,
            *self.other_lines,
        ]
        deduped: list[str] = []
        for line in lines:
            if line not in deduped:
                deduped.append(line)
        return deduped

    @property
    def best_fatal_line(self) -> str:
        if self.fatal_signal_lines:
            return self.fatal_signal_lines[-1]
        if self.fatal_traceback_lines:
            return self.fatal_traceback_lines[-1]
        return ""

    @property
    def best_warning_line(self) -> str:
        if self.warnings:
            return self.warnings[-1]
        if self.budget_clamped_timeouts:
            return self.budget_clamped_timeouts[-1]
        if self.cleanup_timeout_tracebacks:
            return self.cleanup_timeout_tracebacks[-1]
        return ""


def classify_stderr_lines(lines: list[str]) -> StderrClassification:
    classification = StderrClassification()

    for raw_line in lines:
        line = str(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()

        if any(lowered.startswith(prefix) for prefix in _WARNING_CONTEXT_PREFIXES):
            continue

        if (
            lowered.startswith("warning:")
            or lowered.startswith("warning ")
            or _PYTHON_WARNING_RE.match(line)
        ):
            classification.warnings.append(line)
            if "retrying attempt" in lowered:
                classification.retry_warnings.append(line)
            if any(marker in lowered for marker in _BUDGET_MARKERS) or "timed out" in lowered:
                classification.budget_clamped_timeouts.append(line)
            continue

        if "timed out" in lowered:
            classification.budget_clamped_timeouts.append(line)
            classification.other_lines.append(line)
            if any(marker in lowered for marker in _CLEANUP_TIMEOUT_MARKERS):
                classification.cleanup_timeout_tracebacks.append(line)
            continue

        is_traceback_line = lowered.startswith(_TRACEBACK_PREFIXES) or lowered.startswith(
            _TRACEBACK_FRAME_PREFIXES
        )
        if lowered.startswith("timeouterror:") or lowered.endswith("error:"):
            is_traceback_line = True

        if is_traceback_line:
            classification.tracebacks.append(line)
            if any(marker in lowered for marker in _CLEANUP_TIMEOUT_MARKERS):
                classification.cleanup_timeout_tracebacks.append(line)
            continue

        if any(marker in lowered for marker in _CLEANUP_TIMEOUT_MARKERS):
            classification.cleanup_timeout_tracebacks.append(line)
            continue

        if any(marker in lowered for marker in _BUDGET_MARKERS):
            classification.budget_clamped_timeouts.append(line)
            classification.other_lines.append(line)
            continue

        if lowered.startswith(_FATAL_PREFIXES) or any(
            marker in lowered for marker in _FATAL_MARKERS
        ):
            classification.fatal_signal_lines.append(line)
            continue

        classification.other_lines.append(line)

    return classification


def classify_stderr_text(text: str) -> StderrClassification:
    return classify_stderr_lines(str(text or "").splitlines())


def extract_degraded_providers(lines: list[str]) -> list[str]:
    providers: list[str] = []
    for raw_line in lines:
        lowered = str(raw_line or "").lower()
        for provider in _KNOWN_PROVIDERS:
            if provider in lowered and provider not in providers:
                providers.append(provider)
    return providers


__all__ = [
    "StderrClassification",
    "classify_stderr_lines",
    "classify_stderr_text",
    "extract_degraded_providers",
]
