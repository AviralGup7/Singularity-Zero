"""Command handlers keyed by catalog name."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from src.console.context import RequestContext
from src.console.handlers import intel, jobs, notifications, session, snapshot
from src.integration.commands import CommandName

Handler = Callable[[RequestContext], dict[str, Any]]

HANDLERS: dict[str, Handler] = {
    CommandName.HANDSHAKE_OPEN.value: session.handle_handshake_open,
    CommandName.HANDSHAKE_PING.value: session.handle_handshake_ping,
    CommandName.HANDSHAKE_CLOSE.value: session.handle_handshake_close,
    CommandName.SESSION_DEMO.value: session.handle_demo_sign_in,
    CommandName.SESSION_DESCRIBE.value: session.handle_session_describe,
    CommandName.SESSION_REVOKE.value: session.handle_session_revoke,
    CommandName.JOBS_LIST.value: jobs.handle_jobs_list,
    CommandName.JOBS_GET.value: jobs.handle_jobs_get,
    CommandName.JOBS_START.value: jobs.handle_jobs_start,
    CommandName.JOBS_STOP.value: jobs.handle_jobs_stop,
    CommandName.JOBS_EVENTS.value: jobs.handle_jobs_events,
    CommandName.JOBS_SUMMARIES.value: jobs.handle_jobs_summaries,
    CommandName.NOTIFICATIONS_LIST.value: notifications.handle_list,
    CommandName.NOTIFICATIONS_MARK_READ.value: notifications.handle_mark_read,
    CommandName.NOTIFICATIONS_MARK_ALL.value: notifications.handle_mark_all,
    CommandName.NOTIFICATIONS_DELETE.value: notifications.handle_delete,
    CommandName.NOTIFICATIONS_POLICY.value: notifications.handle_policy,
    CommandName.INTEL_LOOKUP.value: intel.handle_lookup,
    CommandName.INTEL_SEED.value: intel.handle_seed,
    CommandName.SNAPSHOT_GET.value: snapshot.handle_snapshot,
    CommandName.STREAM_POLL.value: snapshot.handle_stream_poll,
}
