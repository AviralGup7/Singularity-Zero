"""Custom exception hierarchy for the pipeline."""

__all__ = [
    "PipelineError",
    "ConfigError",
    "StageError",
    "FindingError",
    "ReplayError",
    "AuthError",
    "CacheError",
    "ExternalToolError",
    "ScopeViolationError",
]


class PipelineError(Exception):
    """Base exception for all pipeline-related errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigError(PipelineError):
    """Raised when a configuration value is missing or invalid."""

    pass


class StageError(PipelineError):
    """Raised when a pipeline stage fails during execution."""

    def __init__(self, message: str, stage: str | None = None, details: dict | None = None) -> None:
        super().__init__(message, details)
        self.stage = stage


class FindingError(PipelineError):
    """Raised when a finding fails validation or is malformed."""

    pass


class ReplayError(PipelineError):
    """Raised when a replay operation encounters an error."""

    pass


class AuthError(PipelineError):
    """Raised when authentication or authorization fails."""

    pass


class CacheError(PipelineError):
    """Raised when a cache operation fails."""

    pass


class ExternalToolError(PipelineError):
    """Raised when an external tool execution fails."""

    def __init__(
        self,
        message: str,
        tool: str | None = None,
        exit_code: int | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.tool = tool
        self.exit_code = exit_code


class ScopeViolationError(PipelineError):
    """Raised when a request targets a host, IP, or path outside the defined scan scope."""

    def __init__(
        self,
        message: str,
        target_url: str | None = None,
        reason: str | None = None,
        scope_hosts: list[str] | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.target_url = target_url
        self.reason = reason
        self.scope_hosts = scope_hosts or []
