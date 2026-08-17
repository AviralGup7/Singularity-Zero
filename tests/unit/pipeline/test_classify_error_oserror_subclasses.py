"""Regression: filesystem OSError subclasses must not be retried as transient."""

from __future__ import annotations

import pytest

from src.pipeline.retry.classifier import classify_error


@pytest.mark.unit
@pytest.mark.parametrize(
    "exc",
    [
        FileNotFoundError("missing.bin"),
        PermissionError("denied"),
        IsADirectoryError("is a dir"),
        NotADirectoryError("not a dir"),
        FileExistsError("exists"),
    ],
)
def test_permanent_oserror_subclasses_are_not_retried(exc: OSError) -> None:
    assert classify_error(exc) == "permanent"


@pytest.mark.unit
def test_bare_oserror_stays_transient_for_network_failures() -> None:
    assert classify_error(OSError("network unreachable")) == "transient"


@pytest.mark.unit
def test_connection_errors_remain_transient() -> None:
    assert classify_error(ConnectionError("refused")) == "transient"
    assert classify_error(ConnectionResetError("reset")) == "transient"
    assert classify_error(TimeoutError("timed out")) == "transient"
