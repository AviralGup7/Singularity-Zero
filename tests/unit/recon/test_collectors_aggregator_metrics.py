from src.recon.collectors.aggregator import metrics_summary


def test_metrics_summary_empty():
    summary = metrics_summary({})
    assert summary["total_urls"] == 0
    assert summary["total_errors"] == 0
    assert isinstance(summary["providers"], dict)


def test_metrics_summary_populated():
    stage_meta = {
        "wayback": {"status": "ok", "duration_seconds": 1.2, "new_urls": 5, "errors": 0},
        "commoncrawl": {"status": "ok", "duration_seconds": 0.8, "new_urls": 3, "errors": 1},
    }
    summary = metrics_summary(stage_meta)
    assert summary["total_urls"] == 8
    assert summary["total_errors"] == 1
    assert summary["providers"]["wayback"]["new_urls"] == 5
    assert summary["providers"]["commoncrawl"]["errors"] == 1
