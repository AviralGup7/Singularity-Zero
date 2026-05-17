"""Pre-flight configuration validation for the security pipeline.

Validates pipeline configuration before execution starts, ensuring all
required fields, tools, scope entries, and output directories are valid.

Usage:
    from src.pipeline.validation import validate_config

    ok, report = validate_config(config_dict, scope_file, output_dir)
"""

import ipaddress
import os
import shutil
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = ("target_name", "output_dir", "mode")

COMMON_TOOLS = (
    "subfinder",
    "assetfinder",
    "amass",
    "httpx",
    "gau",
    "waybackurls",
    "katana",
    "nuclei",
)


def _is_valid_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname."""
    if len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    parts = hostname.split(".")
    if not parts:
        return False
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in part):
            return False
    return True


def _is_valid_cidr(cidr: str) -> bool:
    """Check if a string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError, TypeError:
        return False


def _is_valid_scope_entry(entry: str) -> bool:
    """Check if a scope entry is a valid hostname or CIDR."""
    entry = entry.strip()
    if not entry:
        return False
    if "/" in entry:
        return _is_valid_cidr(entry)
    if entry.startswith("*."):
        return _is_valid_hostname(entry[2:])
    return _is_valid_hostname(entry)


def _check_tool_available(tool_name: str) -> bool:
    """Check if a tool is available on PATH."""
    return shutil.which(tool_name) is not None


def _get_disk_usage_mb(path: str) -> tuple[float, float, float]:
    """Get disk usage stats in MB: (total, used, free)."""
    try:
        usage = shutil.disk_usage(path)
        return (
            usage.total / (1024 * 1024),
            usage.used / (1024 * 1024),
            usage.free / (1024 * 1024),
        )
    except OSError:
        return (0.0, 0.0, 0.0)


def validate_config(
    config_dict: dict[str, Any],
    scope_entries: list[str],
    output_dir: str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Validate pipeline configuration before execution.

    Checks:
    1. Required config fields exist
    2. All enabled tools are on PATH
    3. Output directory is writable or can be created
    4. Scope entries are valid hostnames/CIDRs
    5. Disk space is sufficient

    Args:
        config_dict: The loaded configuration dictionary.
        scope_entries: List of scope entries to validate.
        output_dir: Override for output directory path.

    Returns:
        Tuple of (all_passed: bool, report: dict) where report contains
        detailed check results.
    """
    report: dict[str, Any] = {
        "checks": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }
    all_ok = True

    # Check 1: Required config fields
    missing_fields = [f for f in REQUIRED_FIELDS if f not in config_dict]
    fields_passed = len(missing_fields) == 0
    report["checks"].append(
        {
            "name": "required_fields",
            "passed": fields_passed,
            "details": (
                "All required fields present"
                if fields_passed
                else f"Missing fields: {', '.join(missing_fields)}"
            ),
        }
    )
    if not fields_passed:
        all_ok = False

    # Check 2: Tool availability
    tools_config = config_dict.get("tools", {})
    unavailable_tools: list[str] = []
    available_tools: list[str] = []
    for tool_name in COMMON_TOOLS:
        if tools_config.get(tool_name, False):
            if _check_tool_available(tool_name):
                available_tools.append(tool_name)
            else:
                unavailable_tools.append(tool_name)

    tools_ok = len(unavailable_tools) == 0
    report["checks"].append(
        {
            "name": "tool_availability",
            "passed": tools_ok,
            "details": (
                f"All {len(available_tools)} configured tools available"
                if tools_ok
                else f"Missing tools: {', '.join(unavailable_tools)}"
            ),
            "available": available_tools,
            "missing": unavailable_tools,
        }
    )
    if not tools_ok:
        all_ok = False

    # Check 3: Output directory
    target_dir = output_dir or config_dict.get("output_dir", ".")
    output_path = Path(target_dir)
    output_ok = True
    output_details = ""

    if output_path.exists():
        if os.access(str(output_path), os.W_OK):
            output_details = f"Output directory exists and is writable: {output_path}"
        else:
            output_ok = False
            output_details = f"Output directory exists but is NOT writable: {output_path}"
    else:
        # Fix #261: validation must not create directories as a side effect.
        # Check if the nearest existing parent is writable instead.
        parent = output_path
        while parent != parent.parent and not parent.exists():
            parent = parent.parent
        if os.access(str(parent), os.W_OK):
            output_details = f"Output directory will be created (parent writable): {output_path}"
        else:
            output_ok = False
            output_details = f"Cannot create output directory — parent not writable: {parent}"

    report["checks"].append(
        {
            "name": "output_directory",
            "passed": output_ok,
            "details": output_details,
            "path": str(output_path),
        }
    )
    if not output_ok:
        all_ok = False

    # Check 4: Scope validation
    invalid_entries: list[str] = []
    valid_count = 0
    for entry in scope_entries:
        entry = entry.strip()
        if not entry:
            continue
        if _is_valid_scope_entry(entry):
            valid_count += 1
        else:
            invalid_entries.append(entry)

    scope_ok = len(invalid_entries) == 0 and valid_count > 0
    report["checks"].append(
        {
            "name": "scope_validation",
            "passed": scope_ok,
            "details": (
                f"All {valid_count} scope entries are valid"
                if scope_ok
                else f"Invalid scope entries: {', '.join(invalid_entries)}"
            ),
            "valid_count": valid_count,
            "invalid_entries": invalid_entries,
        }
    )
    if not scope_ok:
        all_ok = False

    # Check 5: Disk space
    disk_check_path = output_path if output_path.exists() else output_path.parent
    if not disk_check_path.exists():
        disk_check_path = Path.cwd()
    total_mb, used_mb, free_mb = _get_disk_usage_mb(str(disk_check_path))
    # Fix #262: 100 MB is too low for large scans generating GBs of output.
    min_free_mb = 500
    disk_ok = free_mb >= min_free_mb
    report["checks"].append(
        {
            "name": "disk_space",
            "passed": disk_ok,
            "details": (
                f"Available: {free_mb:.1f} MB, Used: {used_mb:.1f} MB, Total: {total_mb:.1f} MB"
            ),
            "free_mb": round(free_mb, 1),
            "used_mb": round(used_mb, 1),
            "total_mb": round(total_mb, 1),
        }
    )
    if not disk_ok:
        all_ok = False

    report["summary"] = {
        "total": len(report["checks"]),
        "passed": sum(1 for c in report["checks"] if c["passed"]),
        "failed": sum(1 for c in report["checks"] if not c["passed"]),
    }

    return all_ok, report


def format_validation_report(report: dict[str, Any]) -> str:
    """Format the validation report as a human-readable string.

    Args:
        report: The report dict from validate_config().

    Returns:
        Formatted multiline string.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("  Pipeline Configuration Validation Report")
    lines.append("=" * 60)
    lines.append("")

    for check in report["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        symbol = "[+]" if check["passed"] else "[-]"
        lines.append(f"  {symbol} {status}: {check['name']}")
        lines.append(f"      {check['details']}")
        lines.append("")

    summary = report["summary"]
    lines.append("-" * 60)
    lines.append(
        f"  Summary: {summary['passed']}/{summary['total']} checks passed, "
        f"{summary['failed']} failed"
    )
    lines.append("=" * 60)

    return "\n".join(lines)
