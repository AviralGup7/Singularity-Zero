from __future__ import annotations

from src.integration.commands import CATALOG, CommandName, get_command
from src.integration.correlation import normalize_request_id
from src.integration.envelope import RequestEnvelope, ResponseEnvelope
from src.integration.errors import ErrorCode, bad_request, status_for
from src.integration.handshake import HandshakeOffer
from src.integration.protocol import protocol_compatible
from src.integration.retry import advice_for
from src.integration.routes import match_route


def test_protocol_compat() -> None:
    assert protocol_compatible("1.0")
    assert protocol_compatible("1.4")
    assert not protocol_compatible("2.0")
    assert not protocol_compatible("nope")


def test_envelope_roundtrip() -> None:
    req = RequestEnvelope(command="jobs.list", payload={"limit": 10}, subject="Ada")
    cloned = RequestEnvelope.from_mapping(req.to_dict())
    assert cloned.command == "jobs.list"
    assert cloned.subject == "Ada"
    dumped = req.to_dict()
    assert dumped["has_bearer_token"] is False


def test_error_status() -> None:
    err = bad_request("nope", field="url")
    assert err.status == 400
    assert status_for(ErrorCode.RATE_LIMITED) == 429
    env = ResponseEnvelope.from_error("jobs.start", "req-1", err)
    assert env.ok is False
    assert env.error is not None


def test_request_id_normalized() -> None:
    assert normalize_request_id("??").startswith("req-")
    assert normalize_request_id("req-abcdefghij") == "req-abcdefghij"


def test_handshake_rejects_bad_kind() -> None:
    try:
        HandshakeOffer.from_payload({"kind": "wizard"})
    except Exception as exc:  # noqa: BLE001
        assert "kind" in str(exc).lower() or "unsupported" in str(exc).lower()
    else:
        raise AssertionError("expected bad kind")


def test_handshake_protocol_mismatch() -> None:
    try:
        HandshakeOffer.from_payload({"protocol": "9.0", "kind": "demo"})
    except Exception as exc:  # noqa: BLE001
        assert "protocol" in str(exc).lower() or "incompatible" in str(exc).lower()
    else:
        raise AssertionError("expected protocol error")


def test_retry_advice() -> None:
    yes = advice_for(ErrorCode.RATE_LIMITED, attempt=0)
    assert yes.retry is True
    no = advice_for(ErrorCode.BAD_REQUEST)
    assert no.retry is False
    exhausted = advice_for(ErrorCode.UNAVAILABLE, attempt=9)
    assert exhausted.retry is False


def test_catalog_complete() -> None:
    names = {spec.key for spec in CATALOG}
    assert names == {
        item.value for item in CommandName if item is not CommandName.BATCH_EXECUTE
    } | {CommandName.BATCH_EXECUTE.value}
    get_command("jobs.list")


def test_summaries_not_captured_as_id() -> None:
    match = match_route("GET", "/api/console/jobs/summaries")
    assert match.spec.name is CommandName.JOBS_SUMMARIES
    job = match_route("GET", "/api/console/jobs/abc123")
    assert job.spec.name is CommandName.JOBS_GET
    assert job.params["id"] == "abc123"
    listed = match_route("GET", "/api/console/jobs")
    assert listed.spec.name is CommandName.JOBS_LIST
    started = match_route("POST", "/api/console/jobs")
    assert started.spec.name is CommandName.JOBS_START
