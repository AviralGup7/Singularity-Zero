"""Job command handlers."""

from __future__ import annotations

from typing import Any

from src.console.context import RequestContext
from src.console.views import filter_from_query, job_card, job_page
from src.integration.errors import bad_request, not_found
from src.integration.events import StreamFrame
from src.jobs.query import paginate
from src.jobs.simulator import PipelineSimulator
from src.jobs.status import is_terminal_job_status
from src.jobs.summary import summarize_many


def _merged_query(ctx: RequestContext) -> dict[str, Any]:
    merged = dict(ctx.query)
    for key, value in ctx.payload.items():
        merged.setdefault(key, value)
    return merged


def handle_jobs_list(ctx: RequestContext) -> dict[str, Any]:
    query = _merged_query(ctx)
    spec = filter_from_query(query)
    jobs = ctx.runtime.store.list(spec)
    offset = int(query.get("offset") or 0)
    limit = int(query.get("limit") or query.get("page_size") or 50)
    page = paginate(jobs, offset=offset, limit=limit)
    return job_page(page, now=ctx.now)


def handle_jobs_get(ctx: RequestContext) -> dict[str, Any]:
    job_id = ctx.param("id")
    if not job_id:
        raise bad_request("job id required")
    job = ctx.runtime.store.get(job_id)
    if job is None:
        raise not_found("job not found", id=job_id)
    return {"job": job_card(job, now=ctx.now)}


def handle_jobs_start(ctx: RequestContext) -> dict[str, Any]:
    url = str(ctx.payload.get("base_url") or ctx.payload.get("url") or "").strip()
    if not url:
        raise bad_request("base_url required")
    findings = int(ctx.payload.get("findings") or 0)
    fail_at = ctx.payload.get("fail_at")
    fail_at_s = str(fail_at) if fail_at else None
    skip_raw = ctx.payload.get("skip") or []
    skip = frozenset(str(item) for item in skip_raw) if isinstance(skip_raw, list) else frozenset()
    sim = PipelineSimulator(ctx.runtime.store)
    job_id = sim.run(base_url=url, findings=findings, fail_at=fail_at_s, skip=skip)
    job = ctx.runtime.store.get(job_id)
    if job is None:
        raise not_found("job vanished after start", id=job_id)
    if ctx.session is not None:
        ctx.extras["connections"].publish(
            StreamFrame.job({"type": "job.started", "job_id": job_id, "status": job.get("status")}),
            subject=ctx.session.subject,
        )
    return {"job": job_card(job, now=ctx.now), "job_id": job_id}


def handle_jobs_stop(ctx: RequestContext) -> dict[str, Any]:
    job_id = ctx.param("id")
    if not job_id:
        raise bad_request("job id required")
    job = ctx.runtime.store.get(job_id)
    if job is None:
        raise not_found("job not found", id=job_id)
    if is_terminal_job_status(job.get("status")):
        return {"job": job_card(job, now=ctx.now), "already_terminal": True}
    stopped = ctx.runtime.store.request_stop(job_id)
    return {"job": job_card(stopped, now=ctx.now), "already_terminal": False}


def handle_jobs_events(ctx: RequestContext) -> dict[str, Any]:
    job_id = ctx.param("id")
    if not job_id:
        raise bad_request("job id required")
    if ctx.runtime.store.get(job_id) is None:
        raise not_found("job not found", id=job_id)
    events = [event.to_dict() for event in ctx.runtime.store.events.for_job(job_id)]
    return {"job_id": job_id, "events": events, "total": len(events)}


def handle_jobs_summaries(ctx: RequestContext) -> dict[str, Any]:
    jobs = ctx.runtime.store.list(filter_from_query(_merged_query(ctx)))
    return {"summaries": summarize_many(jobs, now=ctx.now), "total": len(jobs)}
