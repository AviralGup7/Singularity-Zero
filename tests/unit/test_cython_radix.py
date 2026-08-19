import pytest

from src.core.frontier.state import radix_sort_timestamps


def test_radix_sort_behavior():
    """Verify that radix_sort_timestamps behaves identically to Python's stable sort."""
    data = [
        ("item1", 100.5),
        ("item2", 50.2),
        ("item3", 200.1),
        ("item4", 50.2),
    ]
    # Expect sorted by timestamp ascending
    result = radix_sort_timestamps(data)
    expected = sorted(data, key=lambda x: x[1])

    assert len(result) == len(expected)
    assert [item[0] for item in result] == [item[0] for item in expected]


def test_cython_radix_fallback():
    """Assert the compiled accelerator when present; skip if it was not built."""
    pytest.importorskip("src.core.frontier._state_cython")
    from src.core.frontier import _state_cython

    data = [("a", 1.5), ("b", 0.5), ("c", 2.5)]
    result = _state_cython.radix_sort_timestamps(data)
    assert [item[0] for item in result] == ["b", "a", "c"]
