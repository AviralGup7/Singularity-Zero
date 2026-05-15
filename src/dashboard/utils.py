"""Dashboard utilities for argument parsing, URL normalization, and scope extraction.

Provides helpers for parsing CLI arguments, normalizing base URLs, extracting
scope targets from text, formatting timestamps, and estimating remaining time.
"""

import argparse
import ipaddress
import re
from urllib.parse import urlparse

from src.core.utils import format_epoch_ist

SCOPE_HOST_RE = re.compile(
    r"(?<![@\w.-])(\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?![\w.-])", re.IGNORECASE
)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the dashboard server.

    Returns:
        Parsed arguments with root, host, port, and config_template.
    """
    parser = argparse.ArgumentParser(description="Cyber Security Test Pipeline - Unified Dashboard")
    parser.add_argument(
        "--root", default="output", help="Directory to serve reports from (accessible at /reports/)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument(
        "--config-template",
        default="configs/config.example.json",
        help="Base config used for new runs",
    )
    return parser.parse_args()


def normalize_base_url(candidate: str) -> tuple[str, str]:
    """Normalize a user-provided URL or hostname into a standard HTTPS URL.

    Args:
        candidate: Raw URL or hostname input.

    Returns:
        Tuple of (normalized_url, lowercase_hostname).

    Raises:
        ValueError: If the input is empty, unsupported scheme, or missing hostname.
    """
    value = candidate.strip()
    if not value:
        raise ValueError("Enter a base URL or hostname.")
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("Could not extract a hostname from that value.")
    return value, hostname


def extract_scope_targets(scope_text: str) -> list[str]:
    in_scope: list[str] = []
    out_of_scope: set[str] = set()
    mode = "in"
    for raw_line in scope_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower().strip(":")
        if lowered in {
            "out of scope",
            "out scope",
            "out of scope targets",
            "out scope targets",
        } or lowered.startswith("out of scope"):
            mode = "out"
            continue
        if lowered in {"in scope", "in scope targets"} or lowered.startswith("in scope"):
            mode = "in"
            continue
        matches = [normalize_scope_host(match.group(0)) for match in SCOPE_HOST_RE.finditer(line)]
        if not matches:
            continue
        if mode == "out":
            out_of_scope.update(matches)
            continue
        for host in matches:
            if host not in in_scope:
                in_scope.append(host)
    return [host for host in in_scope if host not in out_of_scope]


def normalize_scope_host(value: str) -> str:
    cleaned = value.strip().lower().rstrip(".,);]")
    cleaned = cleaned.lstrip("(")
    return cleaned


def root_domain(hostname: str) -> str:
    normalized = hostname.strip().lower().rstrip(".")
    if not normalized:
        return ""
    if normalized == "localhost" or _is_ip_address(normalized):
        return normalized

    labels = normalized.split(".")
    if len(labels) < 3:
        return normalized

    compound_suffixes = {
        ("co", "uk"),
        ("org", "uk"),
        ("gov", "uk"),
        ("ac", "uk"),
        ("com", "au"),
        ("net", "au"),
        ("org", "au"),
        ("co", "in"),
        ("firm", "in"),
        ("com", "br"),
        ("com", "cn"),
        ("com", "sg"),
        ("co", "jp"),
    }
    suffix = tuple(labels[-2:])
    if suffix in compound_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def build_scope_entries(hostname: str, expand_subdomains: bool = True) -> list[str]:
    normalized = hostname.strip().lower().rstrip(".")
    if not normalized:
        return []
    if not expand_subdomains:
        return [normalized]

    base = root_domain(normalized)
    entries = [base]
    if normalized != base:
        entries.append(normalized)
    if "." in base and base != "localhost" and not _is_ip_address(base):
        entries.append(f"*.{base}")
    return entries


def build_scope_entries_from_text(scope_text: str, fallback_hostname: str = "") -> list[str]:
    extracted = extract_scope_targets(scope_text)
    if extracted:
        return extracted
    if fallback_hostname:
        return build_scope_entries(fallback_hostname)
    raise ValueError("No usable in-scope domains were found in the pasted scope.")


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", value.lower()).strip("-.") or "target"


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "estimating"

    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def estimate_remaining(
    progress_percent: int,
    elapsed_seconds: float,
    progress_history: list[tuple[float, int]] | None = None,
) -> float | None:
    if progress_percent >= 100:
        return 0.0

    baseline_remaining: float | None = None
    if progress_percent >= 8:
        estimated_total = elapsed_seconds / (progress_percent / 100)
        baseline_remaining = max(0.0, estimated_total - elapsed_seconds)

    history_remaining: float | None = None
    history = progress_history or []
    if len(history) >= 2:
        first_ts, first_percent = history[0]
        last_ts, last_percent = history[-1]
        percent_delta = max(0, int(last_percent) - int(first_percent))
        time_delta = max(0.0, float(last_ts) - float(first_ts))
        if percent_delta >= 2 and time_delta >= 5.0:
            speed = percent_delta / time_delta
            if speed > 0:
                history_remaining = max(0.0, (100 - progress_percent) / speed)

    if baseline_remaining is not None and history_remaining is not None:
        return (history_remaining * 0.65) + (baseline_remaining * 0.35)
    if history_remaining is not None:
        return history_remaining
    return baseline_remaining


__all__ = [
    "build_scope_entries",
    "build_scope_entries_from_text",
    "estimate_remaining",
    "extract_scope_targets",
    "format_duration",
    "format_epoch_ist",
    "normalize_base_url",
    "normalize_scope_host",
    "parse_args",
    "root_domain",
    "slugify",
]
