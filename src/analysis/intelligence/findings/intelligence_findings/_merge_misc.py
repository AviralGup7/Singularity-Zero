"""Compatibility wrapper for _misc_merge module.

The orchestrator imports from _merge_misc but the implementation lives in _misc_merge.
"""

from ._misc_merge import merge_misc_findings

__all__ = ["merge_misc_findings"]
