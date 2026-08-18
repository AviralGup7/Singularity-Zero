"""Regression tests for real defects from the suspected-bug list."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from src.api_tests.apitester.api_key_workflows.scope import extract_registrable_domain
from src.core.checkpoint.manager import CheckpointData, LocalCheckpointStore
from src.core.ids import generate_run_id, new_job_id, new_worker_id
from src.core.telemetry import normalize_telemetry_event
from src.core.utils.url_validation import detect_dns_rebinding
from src.execution.frontier.chameleon_evasion import TimingPermutator


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://evil.com@trusted.com", "trusted.com"),
        ("https://evil.com@api.trusted.com/v1", "trusted.com"),
        ("https://api.trusted.com/v1", "trusted.com"),
        ("trusted.com", "trusted.com"),
        ("", ""),
        ("https://localhost", "localhost"),
    ],
)
def test_extract_registrable_domain_ignores_userinfo(url: str, expected: str) -> None:
    assert extract_registrable_domain(url) == expected


@pytest.mark.unit
def test_detect_dns_rebinding_sees_ipv6_loopback() -> None:
    def fake_getaddrinfo(host: str, port: object, family: int = 0, *args: object, **kwargs: object):
        if family == socket.AF_INET:
            return []
        return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))]

    with (
        patch("src.core.utils.url_validation.socket.getaddrinfo", side_effect=fake_getaddrinfo),
        patch("src.core.utils.url_validation.time.sleep", return_value=None),
    ):
        result = detect_dns_rebinding("ipv6.internal.test", rounds=1)

    assert "::1" in result["private_ips"]
    assert result["risk_level"] in {"medium", "high", "critical"}


@pytest.mark.unit
def test_new_job_id_is_full_uuid_hex() -> None:
    first = new_job_id()
    second = new_job_id()
    assert len(first) == 32
    assert first != second
    assert int(first, 16) >= 0


@pytest.mark.unit
def test_generate_run_id_not_second_resolution() -> None:
    ids = {generate_run_id() for _ in range(5)}
    assert len(ids) == 5
    assert all(item.startswith("run-") for item in ids)
    assert all(item.count("-") >= 2 for item in ids)


@pytest.mark.unit
def test_checkpoint_from_json_rejects_corrupt_payload() -> None:
    with pytest.raises(ValueError, match="corrupt checkpoint json"):
        CheckpointData.from_json("{not-json")
    with pytest.raises(ValueError, match="corrupt checkpoint json"):
        CheckpointData.from_json("[]")


@pytest.mark.unit
def test_local_checkpoint_store_skips_corrupt_version(tmp_path: Path) -> None:
    store = LocalCheckpointStore(tmp_path)
    run_id = "run-corrupt"
    path = store._version_file(run_id, 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")

    loaded = asyncio.run(store.load(run_id, version=1))
    assert loaded is None


@pytest.mark.unit
def test_normalize_telemetry_keeps_epoch_zero() -> None:
    event = normalize_telemetry_event({"event_type": "x", "stage": "recon", "epoch": 0.0})
    assert event["epoch"] == 0.0


@pytest.mark.unit
def test_chameleon_seed_zero_is_kept() -> None:
    assert TimingPermutator(seed=0.0)._seed == 0.0


@pytest.mark.unit
def test_new_worker_id_is_not_six_hex() -> None:
    wid = new_worker_id("lite-worker-")
    assert wid.startswith("lite-worker-")
    suffix = wid.removeprefix("lite-worker-")
    assert len(suffix) == 32
    assert new_worker_id("lite-worker-") != wid
