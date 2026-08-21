"""Analyst notes attached to jobs."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(slots=True)
class JobNote:
    job_id: str
    author: str
    body: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "author": self.author,
            "body": self.body,
            "timestamp": self.timestamp,
        }


class JobNotes:
    def __init__(self) -> None:
        self._items: list[JobNote] = []

    def add(self, job_id: str, author: str, body: str) -> JobNote:
        note = JobNote(job_id=job_id, author=author, body=body.strip())
        self._items.append(note)
        return note

    def for_job(self, job_id: str) -> list[JobNote]:
        return [item for item in self._items if item.job_id == job_id]

    def __len__(self) -> int:
        return len(self._items)
