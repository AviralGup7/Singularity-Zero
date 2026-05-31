import pytest

from src.core.frontier.ghost_actor_state import ActorState
from src.core.frontier.state import stable_digest


def test_actor_state_rejects_tampered_digest():
    state = ActorState(
        actor_id="actor-1",
        stage="scan",
        data={"count": 1},
        checkpoint_ts=1.0,
        state_digest=stable_digest({"count": 1}),
    )
    payload = state.pack()
    unpacked = ActorState.unpack(payload)
    unpacked.data["count"] = 2

    with pytest.raises(ValueError, match="digest mismatch"):
        ActorState.rehydrate(
            {
                "actor_id": unpacked.actor_id,
                "stage": unpacked.stage,
                "data": unpacked.data,
                "checkpoint_ts": unpacked.checkpoint_ts,
                "state_digest": state.state_digest,
            }
        )


def test_actor_state_rehydrate_does_not_mutate_input():
    payload = {"data": {"x": 1}}
    ActorState.rehydrate(payload)
    assert payload == {"data": {"x": 1}}


def test_actor_state_rehydrate_copies_actor_state_instance():
    original = ActorState(
        actor_id="actor-1",
        stage="scan",
        data={"items": ["a"]},
        checkpoint_ts=1.0,
    )

    rehydrated = ActorState.rehydrate(original)
    rehydrated.data["items"].append("b")

    assert original.data == {"items": ["a"]}
    assert rehydrated.state_digest == stable_digest({"items": ["a"]})
