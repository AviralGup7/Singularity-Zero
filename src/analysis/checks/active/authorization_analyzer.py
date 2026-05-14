"""Legacy compatibility shim for access-control analyzer imports.

Historically this module carried a duplicate AccessControlAnalyzer
implementation that diverged from the canonical automation runtime.
Re-export the canonical implementation so old import paths remain stable
without creating contract drift.
"""

from src.analysis.automation.access_control import AccessControlAnalyzer, EnforcementResult

__all__ = ["AccessControlAnalyzer", "EnforcementResult"]
