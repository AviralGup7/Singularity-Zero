from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from src.core.checkpoint import CheckpointState
from src.core.storage import CheckpointStore


def serialize_checkpoint_state(state: CheckpointState) -> dict[str, Any]:
    payload = state.to_dict()
    return dict(payload)


def deserialize_checkpoint_state(payload: dict[str, Any]) -> CheckpointState:
    return CheckpointState.from_dict(dict(payload))


def persist_checkpoint_state(store: CheckpointStore, state: CheckpointState) -> None:
    store.write(state.pipeline_run_id, state.checkpoint_version, serialize_checkpoint_state(state))


def checkpoint_state_json(state: CheckpointState) -> str:
    return json.dumps(asdict(state), indent=2, default=str)
