"""Backward-compatible import path for schema migration (atlas F-003).

Canonical implementation: :mod:`src.core.contracts.command_envelope`.
"""

from __future__ import annotations

from src.core.contracts.command_envelope import SchemaMigrationRegistry

# Historical atlas name
SchemaUpcaster = SchemaMigrationRegistry

__all__ = ["SchemaMigrationRegistry", "SchemaUpcaster"]
