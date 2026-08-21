from __future__ import annotations

from src.jobs import MemoryJobStore
from src.jobs.export import export_csv_lines, export_rows
from src.jobs.simulator import PipelineSimulator


def test_export_csv() -> None:
    store = MemoryJobStore()
    PipelineSimulator(store).run(base_url="https://exp.test", findings=1)
    job = store.list()[0]
    rows = export_rows(store, now=job["started_at"] + 1)
    assert rows
    lines = export_csv_lines(store, now=job["started_at"] + 1)
    assert lines[0].startswith("id,")
    assert len(lines) == 2
