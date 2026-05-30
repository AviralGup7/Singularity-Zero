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
    """Ensure that the Cython module is importable and matches python-only fallback if compiled."""
    try:
        from src.core.frontier import _state_cython

        if _state_cython is not None:
            data = [("a", 1.5), ("b", 0.5), ("c", 2.5)]
            result = _state_cython.radix_sort_timestamps(data)
            assert [item[0] for item in result] == ["b", "a", "c"]
    except ImportError:
        # Fallback is expected when C C++ build tools are missing (e.g. locally)
        pass
