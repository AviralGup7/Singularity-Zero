"""Re-export shim for the cockpit router module.

The monolithic cockpit.py has been deconstructed into the cockpit/ package
(nodes.py, edges.py, chains.py, forensics.py, notes.py). This shim preserves
backward compatibility by re-exporting the combined router so that existing
imports such as ``from routers.cockpit import router`` continue to work.
"""

from src.dashboard.fastapi.routers.cockpit import router as router

__all__ = ["router"]
