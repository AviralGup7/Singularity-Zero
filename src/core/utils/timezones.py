"""Timezone utilities for IST (Indian Standard Time) timestamp formatting.

Provides functions for generating IST timestamps, run directory stamps,
and formatting epoch/ISO timestamps to IST for consistent pipeline output.
"""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")
IST_LABEL = "IST (+05:30)"

__all__ = [
    "IST",
    "IST_LABEL",
    "format_epoch_ist",
    "format_iso_to_ist",
    "ist_timestamp",
    "now_ist",
    "run_dir_stamp",
]


def now_ist() -> datetime:
    """Get the current time in IST.

    Returns:
        Current datetime in Asia/Kolkata timezone.
    """
    return datetime.now(IST)


def ist_timestamp() -> str:
    """Get the current time as an ISO-formatted IST string.

    Returns:
        ISO 8601 timestamp in IST.
    """
    return now_ist().isoformat()


def run_dir_stamp() -> str:
    """Generate a timestamp string suitable for run directory naming.

    Returns:
        Timestamp in YYYYMMDD-HHMMSS format in IST.
    """
    return now_ist().strftime("%Y%m%d-%H%M%S")


def format_epoch_ist(timestamp: float | int | None) -> str:
    """Format an epoch timestamp to a human-readable IST string.

    Args:
        timestamp: Unix epoch timestamp (seconds), or None.

    Returns:
        Formatted string like '2024-01-15 03:30:45 PM IST', or empty string.
    """
    if timestamp is None:
        return ""
    return datetime.fromtimestamp(float(timestamp), tz=IST).strftime("%Y-%m-%d %I:%M:%S %p IST")


def format_iso_to_ist(value: str | None) -> str:
    """Convert an ISO 8601 timestamp to IST formatted string.

    Args:
        value: ISO 8601 timestamp string, or None.

    Returns:
        Formatted IST string, or original value if parsing fails.
    """
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(IST).strftime("%Y-%m-%d %I:%M:%S %p IST")
