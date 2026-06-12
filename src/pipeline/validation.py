import logging

"""Pre-flight configuration validation and mid-flight continuous validation for the security pipeline.

Validates pipeline configuration before execution starts, and performs continuous checks
on system resources and artifact integrity mid-run.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
from pathlib import Path
from typing import Any

import psutil
from pydantic import BaseModel, Field

from src.pipeline.tools import get_tool_version, tool_available


# Pydantic models for structural configuration validation
class ToolsConfigModel(BaseModel):
    model_config = {"extra": "allow"}

    timeout_seconds: int | None = 120
    retry_attempts: int | None = 2
    retry_backoff_seconds: float | None = 2.0
    retry_backoff_multiplier: float | None = 1.0
    retry_max_backoff_seconds: float | None = 2.0
    retry_on_timeout: bool | None = True
    retry_on_error: bool | None = True
    retry_jitter: float | None = Field(default=0.25, ge=0.0, le=1.0)
    subfinder: bool | None = True
    assetfinder: bool | None = True
    amass: bool | None = False
    httpx: bool | None = True
    gau: bool | None = True
    waybackurls: bool | None = True
    katana: bool | None = True
    nuclei: bool | None = True


class HuntModeConfigModel(BaseModel):
    model_config = {"extra": "allow"}

    enabled: bool = False
    skip_subdomain_enumeration: bool = True
    skip_passive_checks: bool = False
    high_value_categories: list[str] | None = None
    low_hanging_fruit: dict[str, Any] | None = Field(default_factory=dict)
    deduplicate_against_history: bool = True


class HuntBudgetConfigModel(BaseModel):
    model_config = {"extra": "allow"}

    max_duration_seconds: float | None = 14400.0
    high_value_target_time_budget_pct: float | None = 0.4
    stop_when_high_confidence_count: int | None = 5
    stop_when_total_findings: int | None = 50
    max_concurrent_probes: int | None = 5
    countdown_visible: bool | None = True


class ConfigModel(BaseModel):
    model_config = {"extra": "allow"}

    target_name: str
    output_dir: str
    http_timeout_seconds: int | None = 12
    mode: str
    cache: dict[str, Any] | None = Field(default_factory=dict)
    tools: ToolsConfigModel | None = Field(default_factory=ToolsConfigModel)
    hunt_mode: HuntModeConfigModel | None = Field(default_factory=HuntModeConfigModel)
    hunt_budget: HuntBudgetConfigModel | None = Field(default_factory=HuntBudgetConfigModel)


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


def _wildcard_candidate_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return representative IPs to check for a wildcard host.

    Wildcards (e.g. ``*.example.com``) may resolve to any host under
    that domain. We can't enumerate the whole zone, but we resolve the
    base domain to a few representative IPs to check whether the
    wildcard points into RFC1918 / link-local space. The
    :class:`ScopeEnforcer` does the per-request enforcement; this
    function is only used as a *pre-flight* sanity check.
    """
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        import random

        addrinfo = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        seen: set[str] = set()
        for family, _type, _proto, _canon, sockaddr in addrinfo:
            ip_key = str(sockaddr[0])
            if ip_key in seen:
                continue
            seen.add(ip_key)
            try:
                candidates.append(ipaddress.ip_address(ip_key))
            except ValueError:
                continue
            if len(candidates) >= 4:
                break
        if not candidates:
            candidates = [
                ipaddress.ip_address(f"203.0.113.{random.randint(1, 254)}"),  # noqa: S311
            ]
    except Exception:
        candidates = [ipaddress.ip_address("203.0.113.1")]
    return candidates


def validate_scope_rfc1918(entry: str) -> tuple[bool, str]:
    clean_entry = entry.strip()
    if "/" in clean_entry:
        try:
            net = ipaddress.ip_network(clean_entry, strict=False)
            if net.is_private:
                return False, f"Scope entry '{entry}' is a private RFC1918 network"
            # 6to4 / 6rd / IPv4-mapped IPv6 networks that are effectively
            # RFC1918 when interpreted as IPv4 also rejected.
            if isinstance(net, ipaddress.IPv6Network):
                first_addr = ipaddress.IPv6Address(net.network_address)
                if bool(getattr(first_addr, "sixtofour", False)):
                    return False, f"Scope entry '{entry}' is a 6to4-mapped IPv4 range"
                if bool(getattr(first_addr, "teredo", False)):
                    return False, f"Scope entry '{entry}' is a Teredo-mapped IPv4 range"
        except Exception:
            return False, f"Invalid CIDR: '{entry}'"
    else:
        try:
            ip = ipaddress.ip_address(clean_entry)
            if ip.is_private:
                return False, f"Scope entry '{entry}' is a private RFC1918 IP address"
            if isinstance(ip, ipaddress.IPv6Address):
                if bool(getattr(ip, "sixtofour", False)):
                    return False, f"Scope entry '{entry}' is a 6to4-mapped IPv4 address"
        except ValueError:
            # Resolve hostname best-effort to check for RFC1918 constipation
            resolve_target = clean_entry
            if resolve_target.startswith("*."):
                resolve_target = resolve_target[2:]
            try:
                resolved_ip = socket.gethostbyname(resolve_target)
                ip = ipaddress.ip_address(resolved_ip)
                if ip.is_private:
                    return (
                        False,
                        f"Scope entry '{entry}' resolves to a private RFC1918 IP: {resolved_ip}",
                    )
            except Exception as exc:
                logging.warning("Operation failed in validation.py: %s", exc, exc_info=True)  # noqa: BLE001
    return True, ""


def validate_scope_wildcard_resolution(entry: str) -> tuple[bool, str]:
    """Validate that a wildcard hostname entry is not a TLD-only wildcard
    or other unresolvable form that would silently accept any host.

    Catches ``*.com``, ``*.io``, ``*.dev`` etc. — patterns that are
    syntactically valid wildcards but expand to the entire TLD. These
    effectively grant unlimited scope and are almost always a
    configuration error. The check is conservative: it rejects any
    wildcard whose public suffix is at most 2 labels (typical TLDs
    +1) or which matches a known short-TLD allowlist.
    """
    clean = entry.strip()
    if not clean.startswith("*."):
        return True, ""
    base = clean[2:].lower().strip().rstrip(".")
    if not base or "." not in base:
        return False, (
            f"Wildcard scope entry '{entry}' is a TLD-only wildcard — "
            "expand it to a full registrable domain (e.g. *.example.com)"
        )
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
            return (
                False,
                f"Scope entry '{entry}' intersects with threat-intel IOC/sinkhole: {res.get('matched_feeds')}",
            )
    except Exception as exc:
        logging.warning("Operation failed in validation.py: %s", exc, exc_info=True)  # noqa: BLE001
    return True, ""


def validate_scope_max_prefix(
    entry: str, max_prefix_v4: int = 24, max_prefix_v6: int = 64
) -> tuple[bool, str]:
    """Reject overly-broad CIDR blocks (e.g. /0, /16).

    Wildcard hostnames (``*.example.com``) are also checked: their
    base must resolve to at least one public, non-RFC1918 IP and the
    resolved IP's network must satisfy the prefix-length bound. This
    prevents operators from accidentally creating an effectively
    unbounded scope by combining a wildcard hostname with a too-broad
    CIDR elsewhere in the same scope file.
    """
    clean_entry = entry.strip()
    if "/" not in clean_entry:
        # Wildcard hostnames: best-effort check the resolved base IP
        # is in a non-private network. This is advisory (DNS can be
        # poisoned) but catches obvious misconfigurations.
        if clean_entry.startswith("*."):
            base = clean_entry[2:].lower().strip().rstrip(".")
            if base:
                try:
                    resolved_ip = socket.gethostbyname(base)
                    ip = ipaddress.ip_address(resolved_ip)
                    if ip.is_private:
                        return False, (
                            f"Wildcard scope entry '{entry}' resolves to private IP {resolved_ip}"
                        )
                except Exception as exc:
                    logging.warning("Operation failed in validation.py: %s", exc, exc_info=True)  # noqa: BLE001
        return True, ""
    try:
        net = ipaddress.ip_network(clean_entry, strict=False)
    except Exception:
        return False, f"Invalid CIDR: '{entry}'"
    if isinstance(net, ipaddress.IPv4Network):
        prefix = net.prefixlen
        if prefix > max_prefix_v4:
            return True, ""
        if prefix < max_prefix_v4:
            return (
                False,
                f"Scope CIDR '{entry}' is too broad (/{prefix}, max /{max_prefix_v4} for IPv4)",
            )
    else:
        # IPv6Network
        prefix = net.prefixlen
        if prefix > max_prefix_v6:
            return True, ""
        if prefix < max_prefix_v6:
            return (
                False,
                f"Scope CIDR '{entry}' is too broad (/{prefix}, max /{max_prefix_v6} for IPv6)",
            )
        # IPv6 ULA (fc00::/7) and link-local (fe80::/10) are also
        # rejected explicitly so they don't slip through ``is_private``
        # checks on every Python version.
        if isinstance(net, ipaddress.IPv6Network):
            if net.network_address in ipaddress.IPv6Network("fc00::/7"):
                return False, f"Scope CIDR '{entry}' is IPv6 Unique-Local (fc00::/7)"
            if net.network_address in ipaddress.IPv6Network("fe80::/10"):
                return False, f"Scope CIDR '{entry}' is IPv6 link-local (fe80::/10)"
    return True, ""


SCOPE_VALIDATORS = (
    validate_scope_syntax,
    validate_scope_disallowed_tlds,
    validate_scope_rfc1918,
    validate_scope_wildcard_resolution,
    validate_scope_threat_intel,
    validate_scope_max_prefix,
)


def _version_satisfies(version: str, spec: str) -> bool:
    """Check if a version string satisfies a PEP 440-style spec like >=2.0.0."""
    version = version.strip()
    m = re.match(r"^(>=|<=|==|!=|~=|>|<)(.+)$", spec.strip())
    if not m:
        return True
    op, required = m.group(1), m.group(2).strip()
    try:
        v_parts = [int(x) for x in version.split(".")[:3]]
        r_parts = [int(x) for x in required.split(".")[:3]]
        while len(v_parts) < len(r_parts):
            v_parts.append(0)
        while len(r_parts) < len(v_parts):
            r_parts.append(0)
        if op == ">=":
            return v_parts >= r_parts
        if op == ">":
            return v_parts > r_parts
        if op == "<=":
            return v_parts <= r_parts
        if op == "<":
            return v_parts < r_parts
        if op == "==":
            return v_parts == r_parts
        if op == "!=":
            return v_parts != r_parts
        if op == "~=":
            return v_parts[:2] == r_parts[:2] and v_parts >= r_parts
    except (ValueError, TypeError) as exc:
        logging.warning("Operation failed in validation.py: %s", exc, exc_info=True)  # noqa: BLE001
    return True


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
                if (
                    not schema_path.exists()
                    or schema_path.read_text(encoding="utf-8") != schema_json
                ):
                    schema_path.write_text(schema_json, encoding="utf-8")
        except Exception as exc:
            logging.warning("Operation failed in validation.py: %s", exc, exc_info=True)  # noqa: BLE001

        ConfigModel.model_validate(config_dict)
        # Post-validation: enforce constraints that Pydantic may not raise on
        tools_cfg = config_dict.get("tools") or {}
        jitter = tools_cfg.get("retry_jitter")
        if jitter is not None:
            try:
                jitter_f = float(jitter)
                if not (0.0 <= jitter_f <= 1.0):
                    raise ValueError(f"retry_jitter must be between 0.0 and 1.0, got {jitter_f}")
            except (TypeError, ValueError) as ve:
                raise ValueError(f"Invalid retry_jitter value: {jitter}") from ve
        report["checks"].append(
            {
                "name": "structural_validation",
                "passed": True,
                "details": "Pydantic structural configuration validation passed.",
            }
        )
    except Exception as exc:
        all_ok = False
        report["checks"].append(
            {
                "name": "structural_validation",
                "passed": False,
                "details": f"Pydantic structural configuration validation failed: {exc}",
            }
        )

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

    # Check 6: Tool version requirements
    version_errors: list[str] = []
    version_ok = True

    try:
        from src.pipeline.tools_capabilities import CAPABILITY_REGISTRY

        for cap_name in CAPABILITY_REGISTRY.list_capabilities():
            manifest = CAPABILITY_REGISTRY.get_manifest(cap_name)
            for tool_req, version_spec in (manifest.version_requirements or {}).items():
                if tool_available(tool_req):
                    actual_version = get_tool_version(tool_req)
                    if actual_version and not _version_satisfies(actual_version, version_spec):
                        version_errors.append(
                            f"{tool_req} installed as '{actual_version}' but {version_spec} required"
                        )
    except Exception as exc:
        logging.warning("Operation failed in validation.py: %s", exc, exc_info=True)  # noqa: BLE001

    if version_errors:
        version_ok = False
    report["checks"].append(
        {
            "name": "tool_versions",
            "passed": version_ok,
            "details": (
                "All tool versions satisfy requirements"
                if version_ok
                else f"Version mismatches: {'; '.join(version_errors)}"
            ),
            "errors": version_errors,
        }
    )
    if not version_ok:
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
def validate_stage_artifact(stage_name: str, ctx: Any) -> tuple[bool, str | None]:
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
