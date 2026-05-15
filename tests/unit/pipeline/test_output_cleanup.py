import tempfile
import unittest
from pathlib import Path

from src.pipeline.maintenance import prune_output_history


def _write_run(target_root: Path, run_name: str) -> Path:
    run_dir = target_root / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_summary.json").write_text(
        '{"generated_at_utc":"2026-03-29T00:00:00+00:00","counts":{"urls":1}}',
        encoding="utf-8",
    )
    (run_dir / "report.html").write_text("<html></html>", encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
