"""Attack Graph & Risk Intelligence Package.

Houses multi-vulnerability attack chain correlation, CVSS risk modeling,
threat campaign analysis, and severity scoring models.
Raw IOC feed ingestion and indicator parsing reside in `src.intel`.

Subpackages are intentionally imported directly by their callers. Keeping this
module light avoids circular imports between finding classification and the
learning-backed severity model.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "intelligence",
    "version": "3.1.0",
    "description": (
        "Threat intelligence, risk scoring, correlation, campaigns, "
        "and swarm coordination. Subpackages are imported directly by "
        "callers to avoid circular imports."
    ),
    "layer": "intelligence",
    "submodules": (
        "campaigns",
        "correlation",
        "feeds",
        "graph",
        "risk",
        "scoring",
        "swarm",
    ),
    "public_api": (),
    "depends_on": ("core", "analysis"),
    "entry_points": (),
    "health_check": "",
}


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

__all__: list[str] = []
