import json
import tempfile
import unittest
from pathlib import Path

from src.dashboard.launcher_paths import (
    CANONICAL_LAUNCHER_DIRNAME,
    launcher_href_prefix,
    launcher_write_dir,
    resolve_launcher_dir,
)
from src.dashboard.services.query_service_recovery import recover_job_from_launcher


class LauncherPathTests(unittest.TestCase):
    def test_write_dir_is_canonical_underscore_launcher(self) -> None:
        root = Path("/tmp/output-root")
        written = launcher_write_dir(root, "abc123")
        self.assertEqual(written, root / CANONICAL_LAUNCHER_DIRNAME / "abc123")

    def test_resolve_prefers_canonical_then_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / "launcher" / "job-legacy"
            legacy.mkdir(parents=True)
            self.assertEqual(resolve_launcher_dir(root, "job-legacy"), legacy)

            canonical = root / "_launcher" / "job-new"
            canonical.mkdir(parents=True)
            self.assertEqual(resolve_launcher_dir(root, "job-new"), canonical)
            self.assertEqual(launcher_href_prefix(root, "job-new"), "/_launcher/job-new")

    def test_recovery_finds_canonical_write_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job_id = "job-recover"
            dest = launcher_write_dir(root, job_id)
            dest.mkdir(parents=True)
            (dest / "config.json").write_text(
                json.dumps({"base_url": "https://example.com", "target_name": "example.com"}),
                encoding="utf-8",
            )
            (dest / "scope.txt").write_text("example.com\n", encoding="utf-8")
            (dest / "stdout.txt").write_text("Run complete\nRun report: /tmp/x\n", encoding="utf-8")
            (dest / "stderr.txt").write_text("", encoding="utf-8")

            recovered = recover_job_from_launcher(
                output_root=root,
                job_id=job_id,
                stage_labels={"completed": "Completed"},
                progress_prefix="PIPELINE_PROGRESS ",
                path_to_output_href=lambda value: value,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered["status"], "completed")
            self.assertTrue(str(recovered["config_href"]).startswith("/_launcher/"))


if __name__ == "__main__":
    unittest.main()
