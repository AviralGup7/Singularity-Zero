import os
import sys

from src.infrastructure.security.input_validation import (
    FileUploadValidator,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestFileUploadValidator(SecurityTestBase):
    def test_valid_filename(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("report.json")
        assert result.is_valid is True

    def test_dangerous_extension(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("malware.exe")
        assert result.is_valid is False

    def test_path_separator(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("../../etc/passwd")
        assert result.is_valid is False

    def test_null_byte(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("file\x00.txt")
        assert result.is_valid is False

    def test_validate_size(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_size(100)
        assert result.is_valid is True

    def test_validate_size_too_large(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_size(10 * 1024 * 1024)
        assert result.is_valid is False

    def test_validate_content_type(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_content_type("application/json")
        assert result.is_valid is True

    def test_validate_content_type_invalid(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_content_type("application/octet-stream")
        assert result.is_valid is False
