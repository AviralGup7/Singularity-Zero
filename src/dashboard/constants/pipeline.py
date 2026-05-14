PROGRESS_PREFIX = "PIPELINE_PROGRESS "
STAGE_LABELS = {
    "startup": "Preparing run",
    "subdomains": "Enumerating subdomains",
    "live_hosts": "Probing live hosts",
    "urls": "Collecting URLs",
    "parameters": "Extracting parameters",
    "priority": "Ranking targets",
    "passive_scan": "Passive analysis",
    "active_scan": "Active scanning",
    "nuclei": "Running nuclei",
    "access_control": "Access control testing",
    "validation": "Validating findings",
    "intelligence": "Intelligence enrichment",
    "reporting": "Building report",
    "completed": "Completed",
    # Aliases for backward compatibility
    "analysis": "Passive analysis",
}
