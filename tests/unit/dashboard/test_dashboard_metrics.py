import unittest

from src.dashboard.fastapi.dashboard_metrics import (
    build_stage_counts,
    classify_pipeline_stage,
    job_series,
    parse_epoch,
)


class DashboardMetricsTests(unittest.TestCase):
    def test_parse_epoch_iso_and_millis(self) -> None:
        self.assertAlmostEqual(parse_epoch(1_700_000_000), 1_700_000_000)
        self.assertAlmostEqual(parse_epoch(1_700_000_000_000), 1_700_000_000)
        iso = parse_epoch("2026-08-22T00:00:00Z")
        self.assertIsNotNone(iso)
        self.assertGreater(iso or 0, 1_700_000_000)
        self.assertIsNone(parse_epoch("not-a-date"))
        self.assertIsNone(parse_epoch(None))

    def test_classify_stage_prefers_specific_tokens(self) -> None:
        self.assertEqual(classify_pipeline_stage("recon-scan"), "discovery")
        self.assertEqual(classify_pipeline_stage("url-collection"), "collection")
        self.assertEqual(classify_pipeline_stage("passive-analysis"), "analysis")
        self.assertEqual(classify_pipeline_stage("validation"), "validation")
        self.assertEqual(classify_pipeline_stage("write-report"), "reporting")
        self.assertEqual(classify_pipeline_stage("idle"), "other")

    def test_job_series_is_not_synthetic(self) -> None:
        empty = job_series([], now=1_700_000_000)
        self.assertEqual(empty["trend_source"], "empty")
        self.assertEqual(empty["trend_data"], [])
        self.assertEqual(empty["scan_trend"], [])

        now = 1_700_000_000
        jobs = [
            {"started_at": now - 86400, "findings_count": 4},
            {"started_at": now, "findings_count": 2},
            {"started_at": "nope"},
        ]
        series = job_series(jobs, buckets=8, now=now)
        self.assertEqual(series["trend_source"], "jobs")
        self.assertEqual(len(series["trend_data"]), 8)
        self.assertEqual(series["trend_data"][-1], 2)
        self.assertEqual(series["trend_data"][-2], 4)
        self.assertEqual(series["scan_trend"][-1], 1)
        self.assertEqual(series["scan_trend"][-2], 1)
        self.assertNotEqual(series["trend_data"], [max(0, 6 - idx) for idx in range(8)])

    def test_stage_counts_use_token_buckets(self) -> None:
        counts = build_stage_counts(
            [
                {"stage": "recon-scan"},
                {"stage": "httpx-scan"},
                {"stage_label": "unknown-phase"},
            ]
        )
        self.assertEqual(counts["discovery"], 1)
        self.assertEqual(counts["collection"], 1)
        self.assertEqual(counts["other"], 1)


if __name__ == "__main__":
    unittest.main()
