"""Compose job store, auth registry, inbox, and intel aggregator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.auth.sessions import SessionRegistry
from src.intel.aggregator import FeedAggregator
from src.jobs.simulator import PipelineSimulator
from src.jobs.status import JobStatus
from src.jobs.store import MemoryJobStore
from src.jobs.summary import health_from_jobs
from src.notifications.bridge import connect
from src.notifications.inbox import Inbox
from src.notifications.metrics import inbox_stats


@dataclass
class ConsoleRuntime:
    store: MemoryJobStore = field(default_factory=MemoryJobStore)
    sessions: SessionRegistry = field(default_factory=SessionRegistry)
    inbox: Inbox = field(default_factory=Inbox)
    intel: FeedAggregator = field(default_factory=FeedAggregator)

    def __post_init__(self) -> None:
        connect(self.store, self.inbox)

    def sign_in_demo(self, name: str = "Demo Analyst") -> str:
        session = self.sessions.issue_demo(name, "analyst")
        return session.subject

    def run_scan(self, url: str, *, findings: int = 0, fail_at: str | None = None) -> str:
        sim = PipelineSimulator(self.store)
        return sim.run(base_url=url, findings=findings, fail_at=fail_at)

    def snapshot(self, *, now: float) -> dict[str, Any]:
        jobs = self.store.list()
        return {
            "jobs": health_from_jobs(jobs, now=now),
            "notifications": inbox_stats(self.inbox),
            "sessions": len(self.sessions),
            "failed_jobs": self.store.counts().get(JobStatus.FAILED.value, 0),
        }

    def gateway(self) -> object:
        from src.console.gateway import ConsoleGateway

        return ConsoleGateway(self)
