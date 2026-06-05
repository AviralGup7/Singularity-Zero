"""Pre-flight configuration validation and mid-flight continuous validation for the security pipeline.

Validates pipeline configuration before execution starts, and performs continuous checks
on system resources and artifact integrity mid-run.
"""

import ipaddress
import json
import os
import shutil
import socket
from pathlib import Path
from typing import Any, Optional, Dict, List
import psutil
from pydantic import BaseModel, Field

# Pydantic models for structural configuration validation
class ToolsConfigModel(BaseModel):
    model_config = {"extra": "allow"}

    timeout_seconds: Optional[int] = 120
    retry_attempts: Optional[int] = 2
    retry_backoff_seconds: Optional[float] = 2.0
    retry_backoff_multiplier: Optional[float] = 1.0
    retry_max_backoff_seconds: Optional[float] = 2.0
    retry_on_timeout: Optional[bool] = True
    retry_on_error: Optional[bool] = True
    retry_jitter: Optional[float] = Field(default=0.25, ge=0.0, le=1.0)
    subfinder: Optional[bool] = True
    assetfinder: Optional[bool] = True
    amass: Optional[bool] = False
    httpx: Optional[bool] = True
    gau: Optional[bool] = True
    waybackurls: Optional[bool] = True
    katana: Optional[bool] = True
    nuclei: Optional[bool] = True

class ConfigModel(BaseModel):
    model_config = {"extra": "allow"}

    target_name: str
    output_dir: str
    http_timeout_seconds: Optional[int] = 12
    mode: str
    cache: Optional[Dict[str, Any]] = Field(default_factory=dict)
    tools: Optional[ToolsConfigModel] = Field(default_factory=ToolsConfigModel)

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
        hostname = hostname.rstrip(".")
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
    except (ValueError, TypeError):
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


# Semantic Scope Validators
def validate_scope_syntax(entry: str) -> tuple[bool, str]:
    if not _is_valid_scope_entry(entry):
        return False, f"Invalid format: '{entry}'"
    return True, ""


def validate_scope_disallowed_tlds(entry: str) -> tuple[bool, str]:
    disallowed = {".local", ".internal", ".test", ".example", ".invalid", ".localhost"}
    entry_lower = entry.lower().strip()
    for tld in disallowed:
        if entry_lower.endswith(tld) or entry_lower == tld[1:]:
            return False, f"Scope entry '{entry}' uses disallowed TLD: {tld}"
    return True, ""


def validate_scope_rfc1918(entry: str) -> tuple[bool, str]:
    clean_entry = entry.strip()
    if "/" in clean_entry:
        try:
            net = ipaddress.ip_network(clean_entry, strict=False)
            if net.is_private:
                return False, f"Scope entry '{entry}' is a private RFC1918 network"
        except Exception:
            return False, f"Invalid CIDR: '{entry}'"
    else:
        try:
            ip = ipaddress.ip_address(clean_entry)
            if ip.is_private:
                return False, f"Scope entry '{entry}' is a private RFC1918 IP address"
        except ValueError:
            # Resolve hostname best-effort to check for RFC1918 constipation
            resolve_target = clean_entry
            if resolve_target.startswith("*."):
                resolve_target = resolve_target[2:]
            try:
                resolved_ip = socket.gethostbyname(resolve_target)
                ip = ipaddress.ip_address(resolved_ip)
                if ip.is_private:
                    return False, f"Scope entry '{entry}' resolves to a private RFC1918 IP: {resolved_ip}"
            except Exception:
                pass
    return True, ""


def validate_scope_threat_intel(entry: str) -> tuple[bool, str]:
    from src.intelligence.threat_intel import ThreatIntelCorrelator
    correlator = ThreatIntelCorrelator(enable_threat_intel=True)
    query_target = entry
    if query_target.startswith("*."):
        query_target = query_target[2:]
    try:
        res = correlator.match_ioc(query_target)
        if res.get("malicious"):
            return False, f"Scope entry '{entry}' intersects with threat-intel IOC/sinkhole: {res.get('matched_feeds')}"
    except Exception:
        pass
    return True, ""


SCOPE_VALIDATORS = [
    validate_scope_syntax,
    validate_scope_disallowed_tlds,
    validate_scope_rfc1918,
    validate_scope_threat_intel,
]


def validate_config(
    config_dict: dict[str, Any],
    scope_entries: list[str],
    output_dir: str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Validate pipeline configuration before execution.

    Two-pass validation:
    1. Structural Pydantic validation (dumps JSON Schema and validates types/bounds).
    2. Semantic validation on scope entries (syntactic, disallowed TLDs, RFC1918, threat-intel IOCs).
    """
    report: dict[str, Any] = {
        "checks": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }
    all_ok = True

    # 1. Structural Pass (Pydantic & JSON Schema evolution)
    try:
        # Write structural JSON schema version alongside configs
        try:
            schema_dir = Path(__file__).parents[2] / "configs"
            schema_path = schema_dir / "config.schema.json"
            if schema_dir.exists():
                schema_json = json.dumps(ConfigModel.model_json_schema(), indent=2)
                if not schema_path.exists() or schema_path.read_text(encoding="utf-8") != schema_json:
                    schema_path.write_text(schema_json, encoding="utf-8")
        except Exception:
            pass

        ConfigModel.model_validate(config_dict)
        report["checks"].append({
            "name": "structural_validation",
            "passed": True,
            "details": "Pydantic structural configuration validation passed.",
        })
    except Exception as exc:
        all_ok = False
        report["checks"].append({
            "name": "structural_validation",
            "passed": False,
            "details": f"Pydantic structural configuration validation failed: {exc}",
        })

    # Legacy check 1: Required config fields (kept for backward compatibility reports)
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
        in_config = tool_name in tools_config
        is_enabled = bool(tools_config.get(tool_name, False))
        if not in_config or is_enabled:
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

    # Check 4: Scope validation (syntactic + semantic check pipeline)
    invalid_entries: list[str] = []
    valid_count = 0
    scope_errors: list[str] = []

    for entry in scope_entries:
        entry = entry.strip()
        if not entry:
            continue
        
        entry_ok = True
        for validator in SCOPE_VALIDATORS:
            ok, err_msg = validator(entry)
            if not ok:
                entry_ok = False
                scope_errors.append(err_msg)
                break
        
        if entry_ok:
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
                else f"Scope errors: {'; '.join(scope_errors)}"
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
    """Format the validation report as a human-readable string."""
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


# Mid-flight Continuous Validation hooks
def validate_stage_artifact(stage_name: str, ctx: Any) -> tuple[bool, Optional[str]]:
    """Validate output artifacts written by a stage for integrity gate."""
    if not hasattr(ctx, "output_store") or ctx.output_store is None:
        return True, None

    run_dir = ctx.output_store.run_dir

    if stage_name == "subdomains":
        subdomains_file = run_dir / "subdomains.txt"
        if not subdomains_file.exists():
            return False, "subdomains.txt is missing"
        try:
            content = subdomains_file.read_text(encoding="utf-8")
            hosts = [line.strip() for line in content.splitlines() if line.strip()]
            if not hosts:
                return False, "subdomains.txt is empty"
            for host in hosts:
                if not host or len(host) > 253:
                    return False, f"Invalid domain in subdomains.txt: '{host[:20]}...'"
        except Exception as e:
            return False, f"Failed to read/validate subdomains.txt: {e}"

    elif stage_name == "live_hosts":
        txt_file = run_dir / "live_hosts.txt"
        jsonl_file = run_dir / "live_hosts.jsonl"
        if not txt_file.exists() or not jsonl_file.exists():
            return False, "live_hosts files are missing"
        try:
            txt_content = txt_file.read_text(encoding="utf-8")
            hosts = [line.strip() for line in txt_content.splitlines() if line.strip()]
            if not hosts:
                return False, "live_hosts.txt is empty"
            jsonl_content = jsonl_file.read_text(encoding="utf-8")
            for line in jsonl_content.splitlines():
                if line.strip():
                    json.loads(line)
        except Exception as e:
            return False, f"Failed to read/parse live_hosts files: {e}"

    elif stage_name == "urls":
        urls_file = run_dir / "urls.txt"
        if not urls_file.exists():
            return False, "urls.txt is missing"
        try:
            content = urls_file.read_text(encoding="utf-8")
            urls = [line.strip() for line in content.splitlines() if line.strip()]
            if not urls:
                return False, "urls.txt is empty"
            for url in urls:
                if not url.startswith(("http://", "https://")):
                    return False, f"Malformed URL in urls.txt: '{url[:30]}...'"
        except Exception as e:
            return False, f"Failed to read/validate urls.txt: {e}"

    elif stage_name == "parameters":
        params_file = run_dir / "parameters.txt"
        if params_file.exists():
            try:
                params_file.read_text(encoding="utf-8")
            except Exception as e:
                return False, f"Failed to read parameters.txt: {e}"

    elif stage_name == "priority":
        endpoints_file = run_dir / "priority_endpoints.txt"
        scores_file = run_dir / "priority_scores.json"
        if not endpoints_file.exists():
            return False, "priority_endpoints.txt is missing"
        try:
            endpoints_file.read_text(encoding="utf-8")
            if scores_file.exists():
                json.loads(scores_file.read_text(encoding="utf-8"))
        except Exception as e:
            return False, f"Failed to read/validate priority output: {e}"

    elif stage_name in ("active_scan", "nuclei", "analysis"):
        findings_file = run_dir / "findings.json"
        if findings_file.exists():
            try:
                findings = json.loads(findings_file.read_text(encoding="utf-8"))
                if not isinstance(findings, list):
                    return False, "findings.json is not a JSON list"
            except Exception as e:
                return False, f"Failed to parse findings.json: {e}"

    return True, None


def probe_system_resources(output_dir: str | Path) -> tuple[bool, dict[str, Any]]:
    """Probe host resources (disk space, virtual memory, handle/fd count)."""
    details: dict[str, Any] = {}
    is_healthy = True

    # 1. Disk Space check
    path = Path(output_dir)
    disk_check_path = path if path.exists() else path.parent
    if not disk_check_path.exists():
        disk_check_path = Path.cwd()

    total_mb, used_mb, free_mb = _get_disk_usage_mb(str(disk_check_path))
    min_free_mb = 500
    details["disk"] = {
        "free_mb": round(free_mb, 1),
        "used_mb": round(used_mb, 1),
        "total_mb": round(total_mb, 1),
        "passed": free_mb >= min_free_mb,
    }
    if free_mb < min_free_mb:
        is_healthy = False

    # 2. Memory check
    mem = psutil.virtual_memory()
    free_mem_mb = mem.available / (1024 * 1024)
    min_free_mem_mb = 200.0
    details["memory"] = {
        "available_mb": round(free_mem_mb, 1),
        "total_mb": round(mem.total / (1024 * 1024), 1),
        "passed": free_mem_mb >= min_free_mem_mb,
    }
    if free_mem_mb < min_free_mem_mb:
        is_healthy = False

    # 3. File Descriptors / Handles check
    proc = psutil.Process()
    try:
        if hasattr(proc, "num_handles"):
            fd_count = proc.num_handles()
        else:
            fd_count = proc.num_fds()
        max_fds = 10000
        details["file_descriptors"] = {
            "count": fd_count,
            "passed": fd_count < max_fds,
        }
        if fd_count >= max_fds:
            is_healthy = False
    except Exception:
        details["file_descriptors"] = {
            "count": -1,
            "passed": True,
        }

    return is_healthy, details
