"""Infrastructure scheduling module.

Provides resource-aware scheduling for matching tasks to workers
based on system capabilities and current load.
"""

from .bidding import BidWeights, MultiObjectiveBid, bid_for_job, bid_for_task

__all__ = [
    "BidWeights",
    "MultiObjectiveBid",
    "ResourceAwareScheduler",
    "bid_for_job",
    "bid_for_task",
]


def __getattr__(name: str) -> object:
    if name == "ResourceAwareScheduler":
        from .resource_aware import ResourceAwareScheduler

        return ResourceAwareScheduler
    raise AttributeError(name)
