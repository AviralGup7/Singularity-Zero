"""Core algebraic data types and failure domains."""

from src.core.types.failure import DomainFailure, FailureDomain
from src.core.types.result import Err, Ok, Result

__all__ = [
    "DomainFailure",
    "Err",
    "FailureDomain",
    "Ok",
    "Result",
]
