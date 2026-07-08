"""File upload validation for type, size, and content safety."""

import logging
import re

from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.input_validation.base import ValidationResult

logger = logging.getLogger(__name__)


class FileUploadValidator:
    """File upload validation."""

    ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml", ".txt", ".csv", ".log"}
    MAX_FILENAME_LENGTH = 255
    DANGEROUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".js",
        ".ps1", ".sh", ".bash", ".zsh", ".php", ".asp", ".aspx", ".jsp",
        ".cgi", ".pl", ".py", ".rb", ".msi", ".dll", ".so", ".dylib",
    }

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config

    def validate_filename(self, filename: str) -> ValidationResult:
        errors: list[str] = []

        if not filename:
            return ValidationResult(valid=False, errors=["Filename cannot be empty"])

        if len(filename) > self.MAX_FILENAME_LENGTH:
            errors.append(f"Filename exceeds maximum length of {self.MAX_FILENAME_LENGTH}")

        if "/" in filename or "\\" in filename:
            errors.append("Filename cannot contain path separators")

        if "\x00" in filename:
            errors.append("Filename cannot contain null bytes")

        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[1].lower()
            if ext in self.DANGEROUS_EXTENSIONS:
                errors.append(f"File extension '{ext}' is not allowed")

        sanitized = re.sub(r"[^\w\-.]", "_", filename)
        sanitized = sanitized[: self.MAX_FILENAME_LENGTH]

        return ValidationResult(valid=not errors, sanitized=sanitized, errors=errors)

    def validate_size(self, size_bytes: int) -> ValidationResult:
        max_size = self.config.input_validation.max_payload_size_bytes
        if size_bytes > max_size:
            return ValidationResult(
                valid=False,
                errors=[f"File size ({size_bytes} bytes) exceeds maximum ({max_size} bytes)"],
            )
        return ValidationResult(valid=True)

    def validate_content_type(self, content_type: str) -> ValidationResult:
        allowed = self.config.input_validation.allowed_content_types
        if content_type not in allowed:
            return ValidationResult(
                valid=False,
                errors=[
                    f"Content type '{content_type}' is not allowed. Allowed: {', '.join(allowed)}"
                ],
            )
        return ValidationResult(valid=True)
