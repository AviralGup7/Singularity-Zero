"""Command catalog: the contract between the Security Console UI and backend.

Every UI action that talks to domain runtimes (jobs, auth, intel, inbox)
is a named command. The HTTP adapter maps method+path onto these names so
the React client and the Python gateway cannot drift independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthMode(StrEnum):
    PUBLIC = "public"
    SESSION = "session"
    DEMO_OK = "demo_ok"
    BEARER = "bearer"


class CommandName(StrEnum):
    HANDSHAKE_OPEN = "handshake.open"
    HANDSHAKE_PING = "handshake.ping"
    HANDSHAKE_CLOSE = "handshake.close"
    SESSION_DEMO = "session.demo_sign_in"
    SESSION_DESCRIBE = "session.describe"
    SESSION_REVOKE = "session.revoke"
    JOBS_LIST = "jobs.list"
    JOBS_GET = "jobs.get"
    JOBS_START = "jobs.start"
    JOBS_STOP = "jobs.stop"
    JOBS_EVENTS = "jobs.events"
    JOBS_SUMMARIES = "jobs.summaries"
    NOTIFICATIONS_LIST = "notifications.list"
    NOTIFICATIONS_MARK_READ = "notifications.mark_read"
    NOTIFICATIONS_MARK_ALL = "notifications.mark_all_read"
    NOTIFICATIONS_DELETE = "notifications.delete"
    NOTIFICATIONS_POLICY = "notifications.policy"
    INTEL_LOOKUP = "intel.lookup"
    INTEL_SEED = "intel.seed"
    SNAPSHOT_GET = "snapshot.get"
    STREAM_POLL = "stream.poll"
    BATCH_EXECUTE = "batch.execute"


@dataclass(frozen=True, slots=True)
class CommandSpec:
    name: CommandName
    method: str
    path: str
    auth: AuthMode
    capability: str | None
    description: str
    stream: bool = False

    @property
    def key(self) -> str:
        return self.name.value


CATALOG: tuple[CommandSpec, ...] = (
    CommandSpec(
        CommandName.HANDSHAKE_OPEN,
        "POST",
        "/api/console/handshake",
        AuthMode.PUBLIC,
        None,
        "Open a console connection and negotiate protocol + session.",
    ),
    CommandSpec(
        CommandName.HANDSHAKE_PING,
        "POST",
        "/api/console/ping",
        AuthMode.PUBLIC,
        None,
        "Keep-alive; refreshes connection last-seen.",
    ),
    CommandSpec(
        CommandName.HANDSHAKE_CLOSE,
        "POST",
        "/api/console/close",
        AuthMode.SESSION,
        None,
        "Drop the console connection.",
    ),
    CommandSpec(
        CommandName.SESSION_DEMO,
        "POST",
        "/api/console/session/demo",
        AuthMode.PUBLIC,
        None,
        "Issue a demo session (name + role, no JWT).",
    ),
    CommandSpec(
        CommandName.SESSION_DESCRIBE,
        "GET",
        "/api/console/session",
        AuthMode.SESSION,
        None,
        "Describe the current session and capabilities.",
    ),
    CommandSpec(
        CommandName.SESSION_REVOKE,
        "POST",
        "/api/console/session/revoke",
        AuthMode.SESSION,
        None,
        "Revoke the current session.",
    ),
    CommandSpec(
        CommandName.JOBS_LIST,
        "GET",
        "/api/console/jobs",
        AuthMode.SESSION,
        "viewJobs",
        "List jobs with optional filters.",
    ),
    CommandSpec(
        CommandName.JOBS_GET,
        "GET",
        "/api/console/jobs/{id}",
        AuthMode.SESSION,
        "viewJobs",
        "Fetch one job card.",
    ),
    CommandSpec(
        CommandName.JOBS_START,
        "POST",
        "/api/console/jobs",
        AuthMode.SESSION,
        "launchJobs",
        "Start a simulated or queued scan.",
    ),
    CommandSpec(
        CommandName.JOBS_STOP,
        "POST",
        "/api/console/jobs/{id}/stop",
        AuthMode.SESSION,
        "stopJobs",
        "Request a cooperative stop.",
    ),
    CommandSpec(
        CommandName.JOBS_EVENTS,
        "GET",
        "/api/console/jobs/{id}/events",
        AuthMode.SESSION,
        "viewJobs",
        "Job domain events for the timeline.",
    ),
    CommandSpec(
        CommandName.JOBS_SUMMARIES,
        "GET",
        "/api/console/jobs/summaries",
        AuthMode.SESSION,
        "viewJobs",
        "Operator summaries used by the cockpit strip.",
    ),
    CommandSpec(
        CommandName.NOTIFICATIONS_LIST,
        "GET",
        "/api/console/notifications",
        AuthMode.DEMO_OK,
        None,
        "List inbox items without requiring a JWT.",
    ),
    CommandSpec(
        CommandName.NOTIFICATIONS_MARK_READ,
        "PATCH",
        "/api/console/notifications/{id}/read",
        AuthMode.DEMO_OK,
        None,
        "Mark one notification read.",
    ),
    CommandSpec(
        CommandName.NOTIFICATIONS_MARK_ALL,
        "PATCH",
        "/api/console/notifications/read-all",
        AuthMode.DEMO_OK,
        None,
        "Mark the inbox read.",
    ),
    CommandSpec(
        CommandName.NOTIFICATIONS_DELETE,
        "DELETE",
        "/api/console/notifications/{id}",
        AuthMode.DEMO_OK,
        None,
        "Dismiss one notification.",
    ),
    CommandSpec(
        CommandName.NOTIFICATIONS_POLICY,
        "GET",
        "/api/console/notifications/policy",
        AuthMode.PUBLIC,
        None,
        "Tell the UI whether JWT notification HTTP/SSE is allowed.",
    ),
    CommandSpec(
        CommandName.INTEL_LOOKUP,
        "GET",
        "/api/console/intel",
        AuthMode.SESSION,
        "viewFindings",
        "Look up an indicator across seeded feeds.",
    ),
    CommandSpec(
        CommandName.INTEL_SEED,
        "POST",
        "/api/console/intel",
        AuthMode.SESSION,
        "launchJobs",
        "Seed a manual intel vote (offline aggregator).",
    ),
    CommandSpec(
        CommandName.SNAPSHOT_GET,
        "GET",
        "/api/console/snapshot",
        AuthMode.SESSION,
        None,
        "Operator snapshot: jobs + inbox + sessions.",
    ),
    CommandSpec(
        CommandName.STREAM_POLL,
        "GET",
        "/api/console/stream",
        AuthMode.DEMO_OK,
        None,
        "Poll queued connection events (SSE stand-in for demo).",
        stream=True,
    ),
    CommandSpec(
        CommandName.BATCH_EXECUTE,
        "POST",
        "/api/console/batch",
        AuthMode.SESSION,
        None,
        "Execute several commands in one round trip.",
    ),
)

_BY_NAME: dict[str, CommandSpec] = {spec.key: spec for spec in CATALOG}


def get_command(name: str | CommandName) -> CommandSpec:
    key = name.value if isinstance(name, CommandName) else str(name)
    spec = _BY_NAME.get(key)
    if spec is None:
        from src.integration.errors import bad_request

        raise bad_request("unknown command", command=key)
    return spec


def catalog_payload(*, capabilities: frozenset[str] | None = None) -> list[dict[str, str | bool | None]]:
    rows: list[dict[str, str | bool | None]] = []
    for spec in CATALOG:
        if spec.capability and capabilities is not None and spec.capability not in capabilities:
            continue
        rows.append(
            {
                "name": spec.key,
                "method": spec.method,
                "path": spec.path,
                "auth": spec.auth.value,
                "capability": spec.capability,
                "description": spec.description,
                "stream": spec.stream,
            }
        )
    return rows


JWT_NOTIFICATION_PATHS: frozenset[str] = frozenset(
    {
        "/api/notifications",
        "/api/notifications/stream",
    }
)
