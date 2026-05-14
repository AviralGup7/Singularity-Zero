"""Infrastructure scheduling module.

Provides resource-aware scheduling for matching tasks to workers
based on system capabilities and current load.
"""

from .resource_aware import ResourceAwareScheduler

__all__ = ["ResourceAwareScheduler"]
