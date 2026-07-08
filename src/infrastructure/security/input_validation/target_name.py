"""Target name validation to prevent path traversal and injection."""

import logging
import re
import string

from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.input_validation.base import ValidationResult

logger = logging.getLogger(__name__)


class TargetNameValidator:
    """Target name validation to prevent path traversal and injection."""

    VALID_CHARS = set(string.ascii_letters + string.digits + "-_. ")

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._blocked_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.input_validation.blocked_target_patterns
        ]

    def validate(self, name: str) -> ValidationResult:
        errors: list[str] = []

        if not name:
            return ValidationResult(valid=False, errors=["Target name cannot be empty"])

        if len(name) > self.config.input_validation.max_target_name_length:
            errors.append(
                f"Target name exceeds maximum length of "
                f"{self.config.input_validation.max_target_name_length}"
            )

        invalid_chars = set(name) - self.VALID_CHARS
        if invalid_chars:
            errors.append(
                f"Target name contains invalid characters: {''.join(sorted(invalid_chars))}"
            )

        for pattern in self._blocked_patterns:
            if pattern.search(name):
                errors.append("Target name contains blocked pattern")
                break

        if name.startswith((".", "-", "_")):
            errors.append("Target name cannot start with '.', '-', or '_'")

        if name.lower() in ("con", "prn", "aux", "nul", "com1", "lpt1"):
            errors.append("Target name cannot be a reserved system name")

        sanitized = self._sanitize_name(name)

        return ValidationResult(valid=not errors, sanitized=sanitized, errors=errors)

    def _sanitize_name(self, name: str) -> str:
        sanitized = "".join(c for c in name if c in self.VALID_CHARS)
        sanitized = sanitized.strip().strip(".-_")
        sanitized = re.sub(r"[-_\s]+", "-", sanitized)
        return sanitized or "unnamed-target"
