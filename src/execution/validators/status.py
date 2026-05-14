from enum import StrEnum


class ValidationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
