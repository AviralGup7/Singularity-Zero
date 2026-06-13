"""Frontier module - distributed state and evasion components.

This module has been decomposed:
- src.core.frontier.* - pure core algorithms (bloom, state, drl_evasion, etc.)
- src.infrastructure.frontier.* - distributed state components (bloom_mesh, ghost_actor, wal, etc.)
- src.execution.frontier.* - domain-specific evasion (chameleon, wasm)
"""

# No re-exports here to avoid circular dependencies.
# Import directly from the appropriate package:
#   from src.execution.frontier.chameleon import RequestChameleon
#   from src.execution.frontier.chameleon_evasion import ChameleonEvasionEngine
