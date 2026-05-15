import tempfile
import unittest
from pathlib import Path

from src.pipeline.storage import load_config, read_scope


class StorageValidationTests(unittest.TestCase):
    def test_load_config_requires_positive_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                ('{"target_name":"demo","output_dir":"output","http_timeout_seconds":0}'),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(config_path)

    def test_read_scope_rejects_empty_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scope_path = Path(temp_dir) / "scope.txt"
            scope_path.write_text("# comments only\n\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_scope(scope_path)

    def test_load_config_accepts_minimal_valid_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                '{"target_name":"demo","output_dir":"output"}',
                encoding="utf-8",
            )
            config = load_config(config_path)
            self.assertEqual(config.target_name, "demo")
            self.assertEqual(config.output_dir, Path("output"))


if __name__ == "__main__":
    unittest.main()
