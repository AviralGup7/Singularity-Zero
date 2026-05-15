from src.recon.filters import filter_similar


def test_filter_similar_prefers_no_query_and_reduces():
    urls = {
        "https://example.com/a?x=1",
        "https://example.com/a?x=2",
        "https://example.com/a",
        "https://example.com/b/c?x=1",
        "https://example.com/b/c?x=2",
        "https://example.com/b/c",
        "https://example.com/other?z=1",
    }

    out = filter_similar(urls, max_results=2)
    assert len(out) == 2
    # Representatives without query should be preferred
    assert "https://example.com/a" in out
    assert "https://example.com/b/c" in out
