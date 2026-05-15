"""Input validation for the Cyber Security Test Pipeline.

Provides comprehensive input validation to prevent common web
vulnerabilities including SSRF, open redirect, path traversal,
injection attacks, and excessive payload sizes.

Classes:
    ValidationRule: Single validation rule definition
    ValidationResult: Result of input validation
    URLValidator: URL validation with SSRF prevention
    TargetNameValidator: Target name validation
    JobPayloadValidator: Job payload validation
    FileUploadValidator: File upload validation
    InputValidator: Main input validation orchestrator

Usage:
    from src.infrastructure.security.input_validation import InputValidator
    from src.infrastructure.security.config import SecurityConfig

    config = SecurityConfig()
    validator = InputValidator(config)

    result = validator.validate_url("https://example.com/api")
    if not result.is_valid:
        raise ValueError(result.error_message)
"""

import ipaddress
import re
import string
from typing import Any
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, Field

from src.infrastructure.security.config import SecurityConfig


class ValidationResult(BaseModel):
    """Result of an input validation check.

    Attributes:
        valid: Whether the input passed validation.
        sanitized: Sanitized version of the input.
        errors: List of validation error messages.
        warnings: List of non-blocking validation warnings.
    """

    valid: bool = Field(default=True)
    sanitized: str = Field(default="")
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if validation passed."""
        return self.valid and not self.errors

    @property
    def error_message(self) -> str:
        """Get combined error message."""
        return "; ".join(self.errors) if self.errors else ""


class ValidationRule(BaseModel):
    """Single validation rule definition.

    Attributes:
        name: Rule identifier.
        pattern: Regex pattern to match against.
        error_message: Error message if pattern matches (blocklist)
                       or doesn't match (allowlist).
        is_blocklist: True if pattern should be blocked.
    """

    name: str = Field(..., min_length=1)
    pattern: str = Field(..., min_length=1)
    error_message: str = Field(..., min_length=1)
    is_blocklist: bool = Field(default=True)


class URLValidator:
    """URL validation with SSRF and open redirect prevention.

    Validates URLs against allowlists, blocklists, and common
    SSRF attack patterns.

    Attributes:
        config: Security configuration.
        _blocklist_patterns: Compiled blocklist regex patterns.
        _allowed_schemes: Set of allowed URL schemes.
    """

    INTERNAL_IP_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("fc00::/7"),
    ]

    SSRF_PATTERNS = [
        r"localhost",
        r"127\.\d+\.\d+\.\d+",
        r"0\.0\.0\.0",
        r"0x7f\.0\.0\.1",
        r"2130706433",
        r"\[::1\]",
        r"\[::\]",
        r"metadata\.google\.internal",
        r"169\.254\.169\.254",
        r"metadata\.azure\.com",
        r"instance-data\.amazonaws\.com",
    ]

    OPEN_REDIRECT_PATTERNS = [
        r"javascript:",
        r"data:",
        r"vbscript:",
        r"\\x",
        r"\\u",
        r"\\/",
    ]

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the URL validator.

        Args:
            config: Security configuration.
        """
        self.config = config
        self._blocklist_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SSRF_PATTERNS + self.OPEN_REDIRECT_PATTERNS
        ]
        self._allowed_schemes = set(config.input_validation.allowed_url_schemes)

    def validate(self, url: str, *, allow_internal: bool = False) -> ValidationResult:
        """Validate a URL for safety.

        Checks:
        1. URL length
        2. URL parsing
        3. Scheme validation
        4. SSRF pattern detection
        5. Internal IP detection (unless allow_internal)
        6. Open redirect prevention

        Args:
            url: URL string to validate.
            allow_internal: Whether to allow internal/private URLs.

        Returns:
            ValidationResult with validation outcome.
        """
        errors: list[str] = []
        warnings: list[str] = []

        if not url:
            return ValidationResult(
                valid=False,
                errors=["URL cannot be empty"],
            )

        if len(url) > self.config.input_validation.max_url_length:
            errors.append(
                f"URL exceeds maximum length of {self.config.input_validation.max_url_length}"
            )

        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ValidationResult(
                valid=False,
                errors=[f"Invalid URL format: {exc}"],
            )

        if not parsed.scheme:
            errors.append("URL must include a scheme (http:// or https://)")

        if parsed.scheme.lower() not in self._allowed_schemes:
            errors.append(
                f"Scheme '{parsed.scheme}' not allowed. "
                f"Allowed: {', '.join(sorted(self._allowed_schemes))}"
            )

        if not parsed.netloc:
            errors.append("URL must include a hostname")

        for pattern in self._blocklist_patterns:
            if pattern.search(url):
                errors.append("URL contains potentially dangerous pattern")
                break

        if not allow_internal and parsed.hostname:
            if self._is_internal_ip(parsed.hostname):
                errors.append("Access to internal/private IP addresses is not allowed")

        if parsed.username or parsed.password:
            warnings.append("URL contains credentials which will be stripped")

        sanitized = self._sanitize_url(parsed)

        return ValidationResult(
            valid=not errors,
            sanitized=sanitized,
            errors=errors,
            warnings=warnings,
        )

    def validate_redirect_url(
        self,
        url: str,
        allowed_hosts: set[str] | None = None,
    ) -> ValidationResult:
        """Validate a URL for use as a redirect target.

        Prevents open redirect vulnerabilities by ensuring the
        redirect target is within allowed hosts.

        Args:
            url: URL to validate as redirect target.
            allowed_hosts: Set of allowed hostnames.

        Returns:
            ValidationResult with validation outcome.
        """
        errors: list[str] = []

        if not url:
            return ValidationResult(
                valid=False,
                errors=["Redirect URL cannot be empty"],
            )

        if url.startswith("//") or url.startswith("\\"):
            errors.append("Protocol-relative redirects are not allowed")
            return ValidationResult(valid=False, errors=errors)

        if url.startswith("/"):
            if url.startswith("//") or url.startswith("/\\"):
                errors.append("URL starts with path but may be interpreted as protocol-relative")
                return ValidationResult(valid=False, errors=errors)
            return ValidationResult(valid=True, sanitized=url)

        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ValidationResult(
                valid=False,
                errors=[f"Invalid URL format: {exc}"],
            )

        if allowed_hosts and parsed.hostname:
            if parsed.hostname.lower() not in {h.lower() for h in allowed_hosts}:
                errors.append(f"Redirect to '{parsed.hostname}' is not in allowed hosts")

        return ValidationResult(
            valid=not errors,
            sanitized=url,
            errors=errors,
        )

    def _is_internal_ip(self, hostname: str) -> bool:
        """Check if a hostname resolves to an internal IP.

        Checks both literal IP addresses and DNS-resolved IPs
        to defend against DNS rebinding attacks.

        Args:
            hostname: Hostname to check.

        Returns:
            True if the hostname is or resolves to an internal IP.
        """
        # Fast path: check if hostname is a literal IP address
        try:
            addr = ipaddress.ip_address(hostname)
            return any(addr in network for network in self.INTERNAL_IP_RANGES)
        except ValueError:
            pass

        # Check for known SSRF hostnames without DNS resolution
        for pattern in self.SSRF_PATTERNS:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True

        # SECURITY: DNS rebinding protection - resolve hostname and
        # check the resolved IP to prevent bypass via DNS rebinding.
        try:
            import socket

            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for result in results:
                resolved_ip_str = result[4][0]
                addr = ipaddress.ip_address(resolved_ip_str)
                if any(addr in network for network in self.INTERNAL_IP_RANGES):
                    return True
            # Also check IPv6
            results_v6 = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for result in results_v6:
                resolved_ip_str = result[4][0]
                addr = ipaddress.ip_address(resolved_ip_str)
                if any(addr in network for network in self.INTERNAL_IP_RANGES):
                    return True
        except (socket.gaierror, OSError):
            # DNS resolution failed - treat as external (safe)
            pass

        return False

    def _sanitize_url(self, parsed: Any) -> str:
        """Sanitize a parsed URL by removing credentials.

        Args:
            parsed: Parsed URL from urlparse.

        Returns:
            Sanitized URL string.
        """
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        return urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                "",
            )
        )


class TargetNameValidator:
    """Target name validation to prevent path traversal and injection.

    Validates target names used for output directory naming and
    ensures they cannot be used for path traversal attacks.

    Attributes:
        config: Security configuration.
        _blocked_patterns: Compiled blocklist patterns.
    """

    VALID_CHARS = set(string.ascii_letters + string.digits + "-_. ")

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the target name validator.

        Args:
            config: Security configuration.
        """
        self.config = config
        self._blocked_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.input_validation.blocked_target_patterns
        ]

    def validate(self, name: str) -> ValidationResult:
        """Validate a target name.

        Checks:
        1. Length limits
        2. Character allowlist
        3. Blocklist patterns
        4. Path traversal prevention
        5. Reserved name prevention

        Args:
            name: Target name to validate.

        Returns:
            ValidationResult with validation outcome.
        """
        errors: list[str] = []

        if not name:
            return ValidationResult(
                valid=False,
                errors=["Target name cannot be empty"],
            )

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

        return ValidationResult(
            valid=not errors,
            sanitized=sanitized,
            errors=errors,
        )

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a target name by removing invalid characters.

        Args:
            name: Target name to sanitize.

        Returns:
            Sanitized target name.
        """
        sanitized = "".join(c for c in name if c in self.VALID_CHARS)
        sanitized = sanitized.strip().strip(".-_")
        sanitized = re.sub(r"[-_\s]+", "-", sanitized)
        return sanitized or "unnamed-target"


class JobPayloadValidator:
    """Job payload validation to prevent injection attacks.

    Validates job creation payloads to ensure they conform to
    expected schemas and don't contain malicious content.

    Attributes:
        config: Security configuration.
        _url_validator: URL validator for base_url field.
    """

    ALLOWED_MODES = {"idor", "full", "quick", "custom"}
    VALID_OPTION_KEYS = {
        "skip_discovery",
        "skip_analysis",
        "skip_reporting",
        "verbose",
        "debug",
    }

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the job payload validator.

        Args:
            config: Security configuration.
        """
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
        """Validate a job creation payload.

        Args:
            base_url: Target base URL.
            target_name: Target name for output directory.
            mode: Pipeline mode.
            modules: Selected module names.
            runtime_overrides: Runtime environment overrides.
            execution_options: Execution option flags.

        Returns:
            ValidationResult with validation outcome.
        """
        errors: list[str] = []
        warnings: list[str] = []

        url_result = self._url_validator.validate(base_url)
        if not url_result.is_valid:
            errors.extend(url_result.errors)

        if target_name:
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


class FileUploadValidator:
    """File upload validation.

    Validates uploaded files for type, size, and content safety.

    Attributes:
        config: Security configuration.
    """

    ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml", ".txt", ".csv", ".log"}
    MAX_FILENAME_LENGTH = 255
    DANGEROUS_EXTENSIONS = {
        ".exe",
        ".bat",
        ".cmd",
        ".com",
        ".scr",
        ".pif",
        ".vbs",
        ".js",
        ".ps1",
        ".sh",
        ".bash",
        ".zsh",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".cgi",
        ".pl",
        ".py",
        ".rb",
        ".msi",
        ".dll",
        ".so",
        ".dylib",
    }

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the file upload validator.

        Args:
            config: Security configuration.
        """
        self.config = config

    def validate_filename(self, filename: str) -> ValidationResult:
        """Validate an uploaded file's name.

        Args:
            filename: Original filename.

        Returns:
            ValidationResult with validation outcome.
        """
        errors: list[str] = []

        if not filename:
            return ValidationResult(
                valid=False,
                errors=["Filename cannot be empty"],
            )

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

        return ValidationResult(
            valid=not errors,
            sanitized=sanitized,
            errors=errors,
        )

    def validate_size(self, size_bytes: int) -> ValidationResult:
        """Validate file size.

        Args:
            size_bytes: File size in bytes.

        Returns:
            ValidationResult with validation outcome.
        """
        max_size = self.config.input_validation.max_payload_size_bytes

        if size_bytes > max_size:
            return ValidationResult(
                valid=False,
                errors=[f"File size ({size_bytes} bytes) exceeds maximum ({max_size} bytes)"],
            )

        return ValidationResult(valid=True)

    def validate_content_type(self, content_type: str) -> ValidationResult:
        """Validate file content type.

        Args:
            content_type: MIME content type.

        Returns:
            ValidationResult with validation outcome.
        """
        allowed = self.config.input_validation.allowed_content_types

        if content_type not in allowed:
            return ValidationResult(
                valid=False,
                errors=[
                    f"Content type '{content_type}' is not allowed. Allowed: {', '.join(allowed)}"
                ],
            )

        return ValidationResult(valid=True)


class InputValidator:
    """Main input validation orchestrator.

    Provides a unified interface for all input validation operations
    across the pipeline.

    Attributes:
        config: Security configuration.
        url: URL validator instance.
        target_name: Target name validator instance.
        job_payload: Job payload validator instance.
        file_upload: File upload validator instance.
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the input validator.

        Args:
            config: Security configuration.
        """
        self.config = config
        self.url = URLValidator(config)
        self.target_name = TargetNameValidator(config)
        self.job_payload = JobPayloadValidator(config)
        self.file_upload = FileUploadValidator(config)

    def sanitize_string(self, value: str, max_length: int = 1024) -> str:
        """Sanitize a generic string input.

        Removes null bytes, control characters, and trims to max length.

        Args:
            value: String to sanitize.
            max_length: Maximum allowed length.

        Returns:
            Sanitized string.
        """
        value = value.replace("\x00", "")
        value = "".join(c for c in value if c.isprintable() or c in "\n\r\t")
        return value[:max_length].strip()

    def sanitize_dict(
        self,
        data: dict[str, Any],
        max_depth: int = 5,
        _current_depth: int = 0,
    ) -> dict[str, Any]:
        """Recursively sanitize dictionary values.

        Args:
            data: Dictionary to sanitize.
            max_depth: Maximum nesting depth.
            _current_depth: Current recursion depth (internal).

        Returns:
            Sanitized dictionary.
        """
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
        """Check if request size is within limits.

        Args:
            content_length: Content-Length header value.

        Returns:
            ValidationResult with validation outcome.
        """
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
