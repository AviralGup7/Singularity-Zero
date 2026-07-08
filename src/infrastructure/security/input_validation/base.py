"""Base validation types — ValidationResult and ValidationRule."""

from pydantic import BaseModel, Field


class ValidationResult(BaseModel):
    """Result of an input validation check."""

    valid: bool = Field(default=True)
    sanitized: str = Field(default="")
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.valid and not self.errors

    @property
    def error_message(self) -> str:
        return "; ".join(self.errors) if self.errors else ""


class ValidationRule(BaseModel):
    """Single validation rule definition."""

    name: str = Field(..., min_length=1)
    pattern: str = Field(..., min_length=1)
    error_message: str = Field(..., min_length=1)
    is_blocklist: bool = Field(default=True)
