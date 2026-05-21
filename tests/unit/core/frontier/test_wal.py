from __future__ import annotations

from typing import Any

import pytest

from src.core.frontier.state import NeuralState
from src.core.frontier.wal import FrontierWAL


class _DummyRedisClient:
    def __init__(self) -> None:
        self.xrange_calls: list[dict[str, Any]] = []
        self.values: dict[str, bytes] = {}

    def xrange(self, stream_key: str, *, min: str, max: str, count: int) -> list[Any]:  # noqa: A002
        self.xrange_calls.append({"stream_key": stream_key, "min": min, "max": max, "count": count})
        return []

    def set(self, key: str, value: bytes) -> None:
        self.values[key] = value

    def get(self, key: str) -> bytes | None:
        return self.values.get(key)

    def expire(self, key: str, seconds: int) -> None:
        pass


def _make_active_wal() -> FrontierWAL:
    wal = FrontierWAL(redis_url=None, run_id="run")
    wal._active = True  # type: ignore[attr-defined]
    wal._client = _DummyRedisClient()  # type: ignore[attr-defined]
    wal._stream_key = "cyber:wal:run"  # type: ignore[attr-defined]
    return wal


def _install_msgpack_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    # FrontierWAL imports msgpack inside recover_deltas(); stub it so the test
    # can run in minimal environments.
    class _MsgpackStub:
        @staticmethod
        def unpackb(*_args: Any, **_kwargs: Any) -> Any:
            return {}

    monkeypatch.setitem(__import__("sys").modules, "msgpack", _MsgpackStub())


def test_recover_deltas_empty_start_id_uses_dash_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_msgpack_stub(monkeypatch)
    wal = _make_active_wal()
    wal.recover_deltas(start_id="")

    client = wal._client  # type: ignore[attr-defined]
    assert client.xrange_calls[0]["min"] == "-"


def test_recover_deltas_nonempty_start_id_is_exclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_msgpack_stub(monkeypatch)
    wal = _make_active_wal()
    wal.recover_deltas(start_id="1-0")

    client = wal._client  # type: ignore[attr-defined]
    assert client.xrange_calls[0]["min"] == "(1-0"


def test_snapshot_round_trip_anchors_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    wal = _make_active_wal()
    state = NeuralState()
    state.apply_delta({"_wal_id": "10-0", "urls": ["https://snapshot.test"]})

    assert wal.persist_snapshot(state) is True
    recovered = wal.recover_state()

    client = wal._client  # type: ignore[attr-defined]
    assert client.xrange_calls[0]["min"] == "(10-0"
    assert recovered.get_snapshot()["urls"] == ["https://snapshot.test"]
