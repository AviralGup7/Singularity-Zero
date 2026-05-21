"""Centralized progress constants for stage execution and job tracking."""

STAGE_BASELINE_PERCENT = {
    "startup": 2,
    "subdomains": 12,
    "live_hosts": 30,
    "urls": 50,
    "parameters": 62,
    "ranking": 74,
    "priority": 78,
    "passive_scan": 86,
    "active_scan": 88,
    "nuclei": 90,
    "semgrep": 91,
    "access_control": 92,
    "validation": 94,
    "intelligence": 96,
    "reporting": 98,
    "completed": 100,
    # Aliases for backward compatibility
    "analysis": 86,
}

# Sibling mapping for orchestrator stage baseline lookups
_STAGE_BASELINE_PROGRESS = {
    k: v
    for k, v in STAGE_BASELINE_PERCENT.items()
    if k not in {"startup", "completed", "analysis"}
}
