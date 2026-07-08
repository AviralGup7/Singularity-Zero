"""Main input validation orchestrator — unified interface."""

import logging
from typing import Any

from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.input_validation.base import ValidationResult
from src.infrastructure.security.input_validation.file_upload import FileUploadValidator
from src.infrastructure.security.input_validation.job_payload import JobPayloadValidator
from src.infrastructure.security.input_validation.target_name import TargetNameValidator
from src.infrastructure.security.input_validation.url import URLValidator

logger = logging.getLogger(__name__)


class InputValidator:
    """Main input validation orchestrator."""

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.url = URLValidator(config)
        self.target_name = TargetNameValidator(config)
        self.job_payload = JobPayloadValidator(config)
        self.file_upload = FileUploadValidator(config)

    def sanitize_string(self, value: str, max_length: int = 1024) -> str:
        value = value.replace("\x00", "")
        value = "".join(c for c in value if c.isprintable() or c in "\n\r\t")
        return value[:max_length].strip()

    def sanitize_dict(
        self,
        data: dict[str, Any],
        max_depth: int = 5,
        _current_depth: int = 0,
    ) -> dict[str, Any]:
        if _current_depth >= max_depth:
            return {}

        sanitized: dict[str, Any] = {}
        for key, value in data.items():
            clean_key = self.sanitize_string(str(key), 128)
            if isinstance(value, str):
                sanitized[clean_key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[clean_key] = self.sanitize_dict(value, max_depth, _current_depth + 1)
            elif isinstance(value, list):
                sanitized[clean_key] = [
                    self.sanitize_string(str(item), 1024) if isinstance(item, str) else item
                    for item in value[:100]
                ]
            elif isinstance(value, (int, float, bool)):
                sanitized[clean_key] = value
            else:
                sanitized[clean_key] = str(value)[:1024]
        return sanitized

    def check_request_size(self, content_length: int | None) -> ValidationResult:
        max_size = self.config.input_validation.max_request_body_bytes
        if content_length is None:
            return ValidationResult(valid=True)
        if content_length > max_size:
            return ValidationResult(
                valid=False,
                errors=[
                    f"Request body size ({content_length} bytes) exceeds maximum ({max_size} bytes)"
                ],
            )
        return ValidationResult(valid=True)
