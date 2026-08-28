import unittest
from src.infrastructure.cache.cache_manager import CacheManager


class TestCacheInvalidationProtocol(unittest.TestCase):
    def test_cache_generation_bump_and_outbox_events(self) -> None:
        cm = CacheManager()
        self.assertEqual(cm.cache_generation, 1)

        # Store tagged item
        cm.set("finding_123", {"status": "OPEN"}, tags={"finding:F-123", "target:api.example.com"})
        self.assertTrue(cm.exists("finding_123"))

        # Invalidation event from Outbox: FINDING_FALSE_POSITIVE
        purged = cm.handle_outbox_invalidation_event(
            "FINDING_FALSE_POSITIVE",
            {"finding_id": "F-123", "target": "api.example.com"},
        )
        self.assertEqual(purged, 1)
        self.assertFalse(cm.exists("finding_123"))

        # Target removed outbox event
        cm.set("target_scan_1", {"data": "recon"}, tags={"target:api.example.com"})
        cm.set("target_scan_2", {"data": "recon2"}, tags={"target:other.example.com"})
        self.assertTrue(cm.exists("target_scan_1"))
        self.assertTrue(cm.exists("target_scan_2"))

        purged_target = cm.handle_outbox_invalidation_event(
            "TARGET_REMOVED",
            {"target": "api.example.com"},
        )
        self.assertEqual(purged_target, 1)
        self.assertFalse(cm.exists("target_scan_1"))
        self.assertTrue(cm.exists("target_scan_2"))

    def test_l2_cache_crc_verification_fail_open_on_corruption(self, tmp_path=None) -> None:
        """Item 17: CRC-64 verification on L2 cache reads fails open to recompute on corruption."""
        import sqlite3
        import tempfile
        from pathlib import Path
        from src.infrastructure.cache.backends.sqlite import SQLiteBackend

        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "test_crc.db")
            backend = SQLiteBackend(db_path=db_path)

            # Store a valid entry with CRC envelope
            backend.set("cached_probe", {"status": "vulnerable", "cve": "CVE-2026-0001"})
            val = backend.get("cached_probe")
            self.assertIsNotNone(val)
            self.assertEqual(val["cve"], "CVE-2026-0001")

            # Corrupt the underlying data directly in SQLite
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE cache_entries SET value = '{\"_cache_crc64\": \"corrupt_crc\", \"data\": {\"cve\": \"POISONED\"}}' WHERE key = 'cached_probe'")
            conn.commit()
            conn.close()

            # Read must detect CRC mismatch and fail-open to None (never serve poisoned payload)
            corrupt_val = backend.get("cached_probe")
            self.assertIsNone(corrupt_val)
            # Must also purge corrupt record so subsequent writes clean up
            self.assertFalse(backend.exists("cached_probe"))
            backend._close_conn()

    def test_transactional_archival_move_and_manifest(self) -> None:
        """Item 18: Transactional archival prune (archive-then-verify-then-delete) with dry-run and manifest."""
        import json
        import tempfile
        import time
        from pathlib import Path
        from src.pipeline.storage_tiering import transactional_prune_and_archive

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            hot_dir = base / "hot"
            archive_dir = base / "archive"
            hot_dir.mkdir()
            archive_dir.mkdir()

            # Create 2 mock runs
            run_old = hot_dir / "run_2026_01"
            run_old.mkdir()
            (run_old / "scan.json").write_text("{\"findings\": [1,2,3]}", encoding="utf-8")
            (run_old / "report.txt").write_text("A" * 5000, encoding="utf-8")

            run_recent = hot_dir / "run_2026_recent"
            run_recent.mkdir()
            (run_recent / "scan.json").write_text("{\"findings\": []}", encoding="utf-8")

            # 1. Dry Run test
            dry_res = transactional_prune_and_archive(hot_dir, archive_dir, max_age_seconds=-1.0, dry_run=True)
            self.assertTrue(dry_res.dry_run)
            self.assertEqual(len(dry_res.archived_runs), 2)
            self.assertTrue(run_old.exists())
            self.assertTrue(run_recent.exists())

            # 2. Transactional Prune test
            res = transactional_prune_and_archive(hot_dir, archive_dir, max_age_seconds=-1.0, dry_run=False)
            self.assertFalse(res.dry_run)
            self.assertEqual(len(res.archived_runs), 2)
            self.assertEqual(len(res.pruned_runs), 2)

            # Hot directory must be deleted
            self.assertFalse(run_old.exists())
            self.assertFalse(run_recent.exists())

            # Archive directory must contain verified copies (with .gz compression on large files)
            archived_old = archive_dir / "run_2026_01"
            self.assertTrue(archived_old.exists())
            self.assertTrue((archived_old / "scan.json").exists())
            self.assertTrue((archived_old / "report.txt.gz").exists())

            # Manifest must be written and contain run_ids
            manifest_file = archive_dir / "archive_manifest.json"
            self.assertTrue(manifest_file.exists())
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            self.assertIn("run_2026_01", manifest_data)
            self.assertIn("run_2026_recent", manifest_data)


if __name__ == "__main__":
    unittest.main()

