import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.pipeline.cache_backend import PersistentCache
from src.pipeline.maintenance import (
    MaintenanceLock,
    RetentionPolicy,
    main,
    prune_output_history,
)


def _write_run(target_root: Path, run_name: str, counts=None, dry_run=False, age_days=0) -> Path:
    run_dir = target_root / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    if counts is None:
        counts = {"urls": 1}

    # Generate time string for simulated age
    import datetime
    dt = datetime.datetime.utcnow() - datetime.timedelta(days=age_days)
    dt_str = dt.strftime("%Y-%m-%dT%H:%M:%S")

    (run_dir / "run_summary.json").write_text(
        json.dumps({
            "generated_at_utc": dt_str,
            "counts": counts,
            "dry_run": dry_run,
        }),
        encoding="utf-8",
    )
    (run_dir / "report.html").write_text("<html></html>", encoding="utf-8")
    (run_dir / "screenshots.json").write_text("[{}]", encoding="utf-8")
    (run_dir / "screenshot.png").write_text("fake binary data", encoding="utf-8")
    return run_dir


class OutputCleanupTests(unittest.TestCase):
    def test_prune_output_history_keeps_recent_target_runs_and_rebuilds_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            target_root = output_root / "example.com"
            _write_run(target_root, "20260327-010101")
            _write_run(target_root, "20260328-010101")
            newest = _write_run(target_root, "20260329-010101")

            summary = prune_output_history(output_root, keep_target_runs=2, keep_launcher_runs=0)

            self.assertFalse((target_root / "20260327-010101").exists())
            self.assertTrue((target_root / "20260328-010101").exists())
            self.assertTrue(newest.exists())
            self.assertTrue((target_root / "index.html").exists())
            self.assertEqual(len(summary["removed_target_run_dirs"]), 1)

    def test_prune_output_history_removes_stale_partial_timestamp_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            target_root = output_root / "partial.example"
            stale = target_root / "20260327-010101"
            keep = target_root / "20260328-010101"
            newest = target_root / "20260329-010101"
            for path in (stale, keep, newest):
                path.mkdir(parents=True, exist_ok=True)
                (path / "scope.txt").write_text("example.com\n", encoding="utf-8")

            summary = prune_output_history(output_root, keep_target_runs=2, keep_launcher_runs=0)

            self.assertFalse(stale.exists())
            self.assertTrue(keep.exists())
            self.assertTrue(newest.exists())
            self.assertIn(str(stale), summary["removed_target_run_dirs"])

    def test_prune_output_history_limits_launcher_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            launcher_root = output_root / "_launcher"
            for name in ("a1", "a2", "a3"):
                path = launcher_root / name
                path.mkdir(parents=True, exist_ok=True)
                (path / "stdout.txt").write_text("ok", encoding="utf-8")

            summary = prune_output_history(output_root, keep_target_runs=2, keep_launcher_runs=1)

            remaining = sorted(path.name for path in launcher_root.iterdir() if path.is_dir())
            self.assertEqual(len(remaining), 1)
            self.assertEqual(len(summary["removed_launcher_dirs"]), 2)

    def test_prune_output_history_validates_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            with self.assertRaises(ValueError):
                prune_output_history(output_root, keep_target_runs=0)
            with self.assertRaises(ValueError):
                prune_output_history(output_root, keep_launcher_runs=-1)

    def test_retention_policy_significance(self) -> None:
        policy = RetentionPolicy(min_significance_score=5)
        # Dry run has 0 significance
        self.assertEqual(policy.calculate_significance({"dry_run": True}), 0)

        # Significant run with critical/high findings
        run_data = {
            "counts": {"critical": 1, "high": 1},
            "findings": [{"severity": "critical"}, {"severity": "high"}],
        }
        self.assertEqual(policy.calculate_significance(run_data), 25)
        self.assertTrue(policy.should_keep_unconditionally(25))

        # Insignificant run
        low_run_data = {
            "counts": {"low": 1},
            "findings": [{"severity": "low"}],
        }
        self.assertEqual(policy.calculate_significance(low_run_data), 1)
        self.assertFalse(policy.should_keep_unconditionally(1))

    def test_storage_tiering_warm_and_cold(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            target_root = output_root / "tiering.com"

            # 3 runs. We set keep_target_runs = 1 so the older ones are processed.
            # newest run: age 0 days
            _write_run(target_root, "20260606-010101", age_days=0)
            # warm run: age 10 days, high significance so it's not pruned
            warm_run = _write_run(target_root, "20260527-010101", counts={"critical": 2}, age_days=10)
            # cold run: age 100 days, high significance so it's not pruned
            cold_run = _write_run(target_root, "20260226-010101", counts={"critical": 2}, age_days=100)

            summary = prune_output_history(
                output_root,
                keep_target_runs=1,
                keep_launcher_runs=0,
                min_significance_score=5,
            )

            # Warm run should have its screenshots removed
            self.assertFalse((warm_run / "screenshots.json").exists())
            self.assertFalse((warm_run / "screenshot.png").exists())

            # Cold run should be zipped and removed locally
            self.assertFalse(cold_run.exists())
            archive_zip = output_root / "_archive" / f"tiering.com_{cold_run.name}.zip"
            self.assertTrue(archive_zip.exists())

    def test_lockfile_concurrency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path = Path(temp_dir) / "maintenance.lock"
            with MaintenanceLock(lock_path) as lock1:
                self.assertTrue(lock_path.exists())
                # Trying to acquire it again should raise RuntimeError
                with self.assertRaises(RuntimeError):
                    with MaintenanceLock(lock_path):
                        pass

    def test_main_cli_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            target_root = output_root / "cli.com"
            _write_run(target_root, "20260329-010101")

            with patch("src.pipeline.maintenance.emit_info") as mock_emit:
                ret = main(["--output-root", str(output_root), "--keep-target-runs", "1"])
                self.assertEqual(ret, 0)
                mock_emit.assert_called()


if __name__ == "__main__":
    unittest.main()
