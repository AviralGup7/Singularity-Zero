"""Bootstrap package — composition root for cross-package protocol registration.

This package exists outside of any layer (core, infrastructure, pipeline, etc.)
so it can import from all of them without violating architecture contracts.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "bootstrap",
    "version": "3.1.0",
    "description": (
        "Application startup wiring and composition root. Registers "
        "cross-package protocol bindings and orchestrates module startup."
    ),
    "layer": "bootstrap",
    "submodules": (),
    "public_api": ("startup_registration",),
    "depends_on": ("core", "analysis", "pipeline", "infrastructure", "dashboard"),
    "entry_points": (),
    "health_check": "",
}


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

__all__: list[str] = []
