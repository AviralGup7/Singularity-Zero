from src.core.frontier.state import LWWset


def test_lwwset_remove_preserves_epoch_timestamp() -> None:
    """Regression test: timestamp=0.0 must not be treated as None.

    If a remove arrives with ts=0.0 (epoch) it should *not* override a later add.
    """

    lww: LWWset[str] = LWWset()
    lww.add("item", timestamp=1.0)

    # This should NOT delete the item because it is older than the add.
    lww.remove("item", timestamp=0.0)

    assert "item" in lww.to_set()
