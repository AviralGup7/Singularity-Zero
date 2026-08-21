from __future__ import annotations

from src.console.gateway import ConsoleGateway
from src.console.interaction import ConsoleInteraction
from src.console.runtime import ConsoleRuntime
from src.integration.commands import CommandName
from src.integration.envelope import RequestEnvelope
from src.intel.verdict import FeedVote, Verdict


def test_demo_sign_in_then_jobs_and_inbox() -> None:
    ui = ConsoleInteraction()
    signed = ui.demo_sign_in("Ada", "analyst")
    assert signed.ok
    assert ui.subject == "Ada"
    assert "viewJobs" in ui.capabilities
    assert signed.data["notifications_policy"]["skip_jwt_notifications"] is True
    assert signed.data["notifications_policy"]["use_console_inbox"] is True

    started = ui.start_scan("https://app.test", findings=3)
    assert started.ok
    job_id = started.data["job_id"]
    listed = ui.list_jobs()
    assert listed.data["total"] == 1
    assert listed.data["jobs"][0]["id"] == job_id
    assert listed.data["jobs"][0]["findings_count"] == 3

    inbox = ui.list_notifications()
    assert inbox.ok
    assert inbox.data["source"] == "console"
    assert inbox.data["total"] >= 1
    row = inbox.data["notifications"][0]
    assert row["read"] in {0, 1}
    assert "T" in row["created_at"]

    snap = ui.snapshot()
    assert snap.data["jobs"]["total"] == 1


def test_guest_cannot_list_jobs() -> None:
    runtime = ConsoleRuntime()
    runtime.sessions.issue_guest()
    gateway = ConsoleGateway(runtime)
    guest = runtime.sessions.subjects()[0]
    response = gateway.dispatch(
        RequestEnvelope(command=CommandName.JOBS_LIST.value, subject=guest)
    )
    assert response.ok is False
    assert response.status == 403


def test_demo_does_not_need_bearer_for_inbox() -> None:
    ui = ConsoleInteraction()
    ui.demo_sign_in("Nia", "analyst")
    ui.start_scan("https://bad.test", fail_at="active_scan")
    inbox = ui.list_notifications()
    assert inbox.status == 200
    assert inbox.data["unread_count"] >= 1
    nid = str(inbox.data["notifications"][0]["id"])
    marked = ui.call(CommandName.NOTIFICATIONS_MARK_READ.value, {}, id=nid)
    assert marked.ok
    assert marked.data["unread_count"] == 0


def test_intel_url_expands_to_host() -> None:
    ui = ConsoleInteraction()
    ui.handshake("Ada")
    ui.seed_intel("evil.example.com", verdict="malicious")
    found = ui.lookup("https://evil.example.com/x")
    assert found.ok
    assert found.data["result"]["verdict"] == Verdict.MALICIOUS.value


def test_idempotent_start() -> None:
    gateway = ConsoleGateway()
    gateway.runtime.sessions.issue_demo("Ada", "analyst")
    first = gateway.dispatch(
        RequestEnvelope(
            command=CommandName.JOBS_START.value,
            subject="Ada",
            payload={"base_url": "https://once.test"},
            idempotency_key="scan-1",
        )
    )
    second = gateway.dispatch(
        RequestEnvelope(
            command=CommandName.JOBS_START.value,
            subject="Ada",
            payload={"base_url": "https://once.test"},
            idempotency_key="scan-1",
        )
    )
    assert first.data["job_id"] == second.data["job_id"]
    assert len(gateway.runtime.store) == 1


def test_stop_terminal_is_noop() -> None:
    ui = ConsoleInteraction()
    ui.demo_sign_in("Ada")
    started = ui.start_scan("https://done.test")
    job_id = str(started.data["job_id"])
    stopped = ui.call(CommandName.JOBS_STOP.value, {}, id=job_id)
    assert stopped.ok
    assert stopped.data["already_terminal"] is True


def test_unknown_command() -> None:
    gateway = ConsoleGateway()
    response = gateway.dispatch(RequestEnvelope(command="nope.command"))
    assert response.ok is False
    assert response.status == 400


def test_missing_session() -> None:
    gateway = ConsoleGateway()
    response = gateway.dispatch(RequestEnvelope(command=CommandName.JOBS_LIST.value))
    assert response.status == 401


def test_batch_snapshot_and_jobs() -> None:
    ui = ConsoleInteraction()
    ui.demo_sign_in("Ada")
    ui.start_scan("https://batch.test")
    batched = ui.call(
        CommandName.BATCH_EXECUTE.value,
        {
            "commands": [
                {"command": CommandName.JOBS_LIST.value},
                {"command": CommandName.SNAPSHOT_GET.value},
            ]
        },
    )
    assert batched.ok
    assert batched.data["count"] == 2
    assert batched.data["results"][0]["ok"] is True


def test_stream_poll_after_scan() -> None:
    ui = ConsoleInteraction()
    ui.handshake("Ada")
    ui.start_scan("https://live.test", findings=1)
    polled = ui.poll()
    assert polled.ok
    types = {event["type"] for event in polled.data["events"]}
    assert "heartbeat" in types or any("job" in str(item) for item in types)


def test_http_adapter_demo_flow() -> None:
    ui = ConsoleInteraction()
    opened = ui.http_call(
        "POST",
        "/api/console/session/demo",
        body={"name": "Ada", "role": "analyst"},
    )
    assert opened.status == 200
    ui.subject = str(opened.body["data"]["session"]["subject"])
    ui.connection_id = str(opened.body["data"]["connection_id"])
    listed = ui.http_call("GET", "/api/console/jobs")
    assert listed.status == 200
    policy = ui.http_call("GET", "/api/console/notifications/policy")
    assert policy.body["data"]["skip_jwt_notifications"] is True


def test_http_unknown_path() -> None:
    ui = ConsoleInteraction()
    missing = ui.http_call("GET", "/api/console/nope")
    assert missing.status == 404


def test_seed_lookup_many_via_text() -> None:
    runtime = ConsoleRuntime()
    runtime.sessions.issue_demo("Ada", "analyst")
    runtime.intel.seed("8.8.8.8", FeedVote(source="manual", verdict=Verdict.HARMLESS, score=0.1))
    gateway = ConsoleGateway(runtime)
    response = gateway.dispatch(
        RequestEnvelope(
            command=CommandName.INTEL_LOOKUP.value,
            subject="Ada",
            payload={"text": "see 8.8.8.8 and https://ok.example"},
        )
    )
    assert response.ok
    assert response.data["count"] >= 1
