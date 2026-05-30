"""Standalone registry of pipeline stages to prevent circular dependencies."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineStage:
    key: str
    label: str
    percent_start: int
    percent_end: int
    owns_layers: tuple[str, ...]


PIPELINE_STAGES: tuple[PipelineStage, ...] = (
    PipelineStage("startup", "Load config and initialize runtime", 0, 5, ("core", "platform")),
    PipelineStage("subdomains", "Enumerate subdomains", 5, 15, ("recon",)),
    PipelineStage(
        "live_hosts", "Probe live hosts and enrich services", 15, 30, ("recon", "analysis")
    ),
    PipelineStage("urls", "Collect and normalize URLs", 30, 45, ("recon",)),
    PipelineStage("parameters", "Extract URL parameters", 45, 55, ("recon",)),
    PipelineStage(
        "ranking", "Rank and select deep-analysis targets", 55, 62, ("recon", "analysis")
    ),
    PipelineStage(
        "passive_scan",
        "Run passive detection and analysis",
        62,
        72,
        ("analysis", "detection"),
    ),
    PipelineStage(
        "active_scan",
        "Run active scanning probes",
        72,
        80,
        ("analysis", "execution"),
    ),
    PipelineStage("nuclei", "Execute nuclei validation checks", 80, 86, ("execution",)),
    PipelineStage(
        "access_control",
        "Test access control and authorization",
        86,
        90,
        ("analysis", "execution"),
    ),
    PipelineStage(
        "validation",
        "Validate findings with active probes",
        90,
        94,
        ("execution",),
    ),
    PipelineStage(
        "intelligence",
        "Merge intelligence and enrich findings",
        94,
        97,
        ("intelligence",),
    ),
    PipelineStage(
        "reporting",
        "Generate reports and dashboard",
        97,
        100,
        ("reporting", "ui"),
    ),
)


def pipeline_flow_manifest() -> list[dict[str, object]]:
    """Return the static list of all stages in the pipeline."""
    return [
        {
            "key": stage.key,
            "label": stage.label,
            "percent_start": stage.percent_start,
            "percent_end": stage.percent_end,
            "owns_layers": list(stage.owns_layers),
        }
        for stage in PIPELINE_STAGES
    ]
