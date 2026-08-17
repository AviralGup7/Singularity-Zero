"""Job payload validation to prevent injection attacks."""

import logging
import re

from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.input_validation.base import ValidationResult
from src.infrastructure.security.input_validation.url import URLValidator

logger = logging.getLogger(__name__)


class JobPayloadValidator:
    """Job payload validation to prevent injection attacks."""

    ALLOWED_MODES = {"idor", "full", "quick", "custom"}
    VALID_OPTION_KEYS = {
        "skip_discovery",
        "skip_analysis",
        "skip_reporting",
        "verbose",
        "debug",
    }

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._url_validator = URLValidator(config)

    def validate(
        self,
        base_url: str,
        target_name: str = "",
        mode: str = "idor",
        modules: list[str] | None = None,
        runtime_overrides: dict[str, str] | None = None,
        execution_options: dict[str, bool] | None = None,
    ) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        url_result = self._url_validator.validate(base_url)
        if not url_result.is_valid:
            errors.extend(url_result.errors)

        if target_name:
            from src.infrastructure.security.input_validation.target_name import TargetNameValidator

            name_validator = TargetNameValidator(self.config)
            name_result = name_validator.validate(target_name)
            if not name_result.is_valid:
                errors.extend(name_result.errors)

        if mode not in self.ALLOWED_MODES:
            errors.append(
                f"Invalid mode '{mode}'. Allowed: {', '.join(sorted(self.ALLOWED_MODES))}"
            )

        if modules is not None:
            if not isinstance(modules, list):
                errors.append("Modules must be a list")
            elif len(modules) > 50:
                errors.append("Cannot select more than 50 modules")
            else:
                for module in modules:
                    if not isinstance(module, str) or not module.strip():
                        errors.append("Each module name must be a non-empty string")
                        break
                    if not re.match(r"^[a-zA-Z0-9_-]+$", module):
                        errors.append(f"Invalid module name: {module}")
                        break

        if runtime_overrides is not None:
            if not isinstance(runtime_overrides, dict):
                errors.append("Runtime overrides must be a dictionary")
            elif len(runtime_overrides) > 20:
                errors.append("Cannot have more than 20 runtime overrides")
            else:
                for key, value in runtime_overrides.items():
                    if not isinstance(key, str) or not key.strip():
                        errors.append("Override keys must be non-empty strings")
                        break
                    if len(key) > 128:
                        errors.append(f"Override key too long: {key[:50]}...")
                        break
                    if len(str(value)) > 1024:
                        errors.append(f"Override value too long for key: {key}")
                        break

        if execution_options is not None:
            if not isinstance(execution_options, dict):
                errors.append("Execution options must be a dictionary")
            else:
                for key in execution_options:
                    if key not in self.VALID_OPTION_KEYS:
                        warnings.append(f"Unknown execution option: {key}")

        return ValidationResult(
            valid=not errors,
            sanitized=base_url if url_result.is_valid else "",
            errors=errors,
            warnings=warnings,
        )
