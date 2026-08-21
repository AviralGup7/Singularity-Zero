"""Named scan playbooks the console can launch."""

from __future__ import annotations

from dataclasses import dataclass

from src.jobs.modes import ScanMode, get_mode
from src.jobs.simulator import PipelineSimulator
from src.jobs.store import MemoryJobStore


@dataclass(frozen=True, slots=True)
class Playbook:
    name: str
    mode: ScanMode
    fail_fast: bool = False


def playbook(name: str) -> Playbook:
    mode = get_mode(name)
    return Playbook(name=mode.key, mode=mode, fail_fast=mode.key in {"idor", "ssrf"})


def run_playbook(store: MemoryJobStore, url: str, name: str = "standard") -> str:
    book = playbook(name)
    sim = PipelineSimulator(store)
    return sim.run(base_url=url, findings=0 if book.fail_fast else 2)
