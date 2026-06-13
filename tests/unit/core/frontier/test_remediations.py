import pytest

from src.core.frontier.ghost_actor import ScanActor
from src.core.frontier.ghost_vfs import GhostVFS
from src.execution.frontier.chameleon_evasion import ChameleonEvasionEngine, HMMEvasionModel


def test_scan_actor_deep_merge():
    def dummy_logic(task_input, state):
        return {}

    actor = ScanActor("test-actor", dummy_logic)
    actor.state = {
        "nested": {"a": 1, "b": {"c": 2}},
        "list_val": [1, 2],
        "set_val": {1, 2},
        "other": "val",
    }

    delta = {
        "nested": {"b": {"d": 3}, "e": 4},
        "list_val": [2, 3],
        "set_val": [3, 4],
        "other": "new_val",
    }

    actor._merge_recovered_delta(delta)

    assert actor.state["nested"] == {"a": 1, "b": {"c": 2, "d": 3}, "e": 4}
    assert set(actor.state["list_val"]) == {1, 2, 3}
    assert actor.state["set_val"] == {1, 2, 3, 4}
    assert actor.state["other"] == "new_val"


def test_chameleon_evasion_hmm_independent_of_ppo():
    engine = ChameleonEvasionEngine()
    assert isinstance(engine.hmm, HMMEvasionModel)

    # Verify we can update observations and get evasion configs without PPO imports
    engine.update_observation(200)
    config = engine.get_evasion_config()
    assert config["state"] == "undetected"

    engine.update_observation(429)
    config = engine.get_evasion_config()
    assert config["state"] != "undetected"
    assert engine.hmm.get_current_state() != HMMEvasionModel.STATE_UNDETECTED


def test_ghost_vfs_path_validation_and_stubs():
    vfs = GhostVFS(principal="system")

    # Test path validation helper
    vfs.write_file("valid/path.txt", b"hello")
    assert vfs.read_file("valid/path.txt") == b"hello"

    with pytest.raises(ValueError):
        vfs.write_file("../traversal.txt", b"hack")

    with pytest.raises(ValueError):
        vfs.write_file("/absolute/path.txt", b"hack")

    with pytest.raises(ValueError):
        vfs.write_file("C:\\windows\\path.txt", b"hack")
