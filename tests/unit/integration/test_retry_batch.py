from __future__ import annotations

from src.integration.batch import MAX_BATCH, parse_batch
from src.integration.errors import ErrorCode, IntegrationError
from src.integration.retry import advice_for, parse_retry_after


def test_parse_batch_rejects_nested() -> None:
    try:
        parse_batch({"commands": [{"command": "batch.execute"}]})
    except IntegrationError as exc:
        assert exc.code is ErrorCode.BAD_REQUEST
    else:
        raise AssertionError("nested batch")


def test_parse_batch_limit() -> None:
    items = [{"command": "jobs.list"}] * (MAX_BATCH + 1)
    try:
        parse_batch({"commands": items})
    except IntegrationError as exc:
        assert "too large" in str(exc)
    else:
        raise AssertionError("limit")


def test_parse_retry_after() -> None:
    assert parse_retry_after("1.5") == 1.5
    assert parse_retry_after("nope") is None
    assert parse_retry_after("-1") is None
    assert advice_for(ErrorCode.INTERNAL, attempt=1).retry is True
