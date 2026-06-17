"""Shared SQL injection detection signals."""

from src.core.utils.sqli_signals import SQL_ERROR_RE, SQL_PARAM_NAMES

__all__ = ["SQL_ERROR_RE", "SQL_PARAM_NAMES"]
