"""Cockpit sub-router aggregation and mounting.

This package deconstructs the monolithic cockpit router into single-concern
files while re-exporting all endpoint functions to preserve seamless backward
compatibility.
"""

from fastapi import APIRouter

from .edges import router as edges_router
from .forensics import get_forensic_exchange
from .forensics import router as forensics_router
from .nodes import get_cockpit_graph
from .nodes import router as nodes_router
from .notes import get_cockpit_events
from .notes import router as notes_router

router = APIRouter()

router.include_router(nodes_router)
router.include_router(edges_router)
router.include_router(forensics_router)
router.include_router(notes_router)

__all__ = ["router", "get_cockpit_events", "get_cockpit_graph", "get_forensic_exchange"]
