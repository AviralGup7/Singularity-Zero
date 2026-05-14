from types import SimpleNamespace

from src.recon.collectors import aggregator_stream


def test_collect_urls_stream_monkeypatched(monkeypatch):
    # Setup providers to return predictable sets
    monkeypatch.setattr(
        "src.recon.collectors.providers.wayback.collect_for_hosts",
        lambda hosts, timeout_seconds, per_host_limit, max_workers, progress_callback=None: (
            {"https://a/", "https://b/"},
            {"status": "ok", "new_urls": 2},
        ),
    )
    monkeypatch.setattr(
        "src.recon.collectors.providers.commoncrawl.collect_for_hosts",
        lambda hosts, timeout_seconds, per_host_limit, max_workers, progress_callback=None: (
            {"https://b/", "https://c/"},
            {"status": "ok", "new_urls": 2},
        ),
    )
    monkeypatch.setattr(
        "src.recon.collectors.providers.urlscan.collect_for_hosts",
        lambda hosts, timeout_seconds, per_host_limit, max_workers, progress_callback=None: (
            {"https://d/"},
            {"status": "ok", "new_urls": 1},
        ),
    )
    monkeypatch.setattr(
        "src.recon.collectors.providers.otx.collect_for_hosts",
        lambda hosts, timeout_seconds, per_host_limit, max_workers, progress_callback=None: (
            set(),
            {"status": "empty", "new_urls": 0},
        ),
    )
    monkeypatch.setattr(
        "src.recon.collectors.providers.simplecrawler.collect_for_hosts",
        lambda hosts, timeout_seconds, per_host_limit, max_workers, progress_callback=None: (
            {"https://e/"},
            {"status": "ok", "new_urls": 1},
        ),
    )

    config = SimpleNamespace(
        tools={
            "waybackurls": True,
            "commoncrawl": True,
            "urlscan": True,
            "otx": True,
            "katana": True,
        },
        filters={},
        waybackurls={},
        commoncrawl={},
        urlscan={},
        otx={},
        katana={},
    )

    gen = aggregator_stream.collect_urls_stream({"https://example.com"}, ["example.com"], config)
    it = iter(gen)
    seen = []
    while True:
        try:
            seen.append(next(it))
        except StopIteration as e:
            stage_meta = e.value
            break

    assert set(seen) == {"https://a/", "https://b/", "https://c/", "https://d/", "https://e/"}
    assert isinstance(stage_meta, dict)
