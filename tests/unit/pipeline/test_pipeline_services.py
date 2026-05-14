import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.pipeline.services.output_store import PipelineOutputStore
from src.pipeline.services.tool_execution import (
    RetryPolicy,
    ToolExecutionService,
)
from src.pipeline.storage import load_config


class ToolRetryAndOutputStoreTests(unittest.TestCase):
    def test_load_config_accepts_concurrency_and_output_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                (
                    '{"target_name":"demo","output_dir":"output",'
                    '"concurrency":{"nuclei_workers":3},'
                    '"output":{"dedupe_aliases":true}}'
                ),
                encoding="utf-8",
            )
            config = load_config(config_path)
            self.assertEqual(config.concurrency["nuclei_workers"], 3)
            self.assertTrue(config.output["dedupe_aliases"])

    def test_tool_execution_service_retries_failed_process_with_backoff(self) -> None:
        service = ToolExecutionService()
        retry_policy = RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=1.0,
            backoff_multiplier=2.0,
            max_backoff_seconds=8.0,
        )
        failed = subprocess.CompletedProcess(args=["demo"], returncode=1, stdout="", stderr="boom")
        succeeded = subprocess.CompletedProcess(args=["demo"], returncode=0, stdout="ok", stderr="")

        with (
            patch.object(service, "resolve_command", return_value=["demo"]),
            patch.object(service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=[failed, succeeded],
            ) as mocked_run,
            patch("src.pipeline.retry.time.sleep") as mocked_sleep,
        ):
            result = service.run_command(["demo"], timeout=5, retry_policy=retry_policy)

        self.assertEqual(result, "ok")
        self.assertEqual(mocked_run.call_count, 2)
        mocked_sleep.assert_called_once()
        self.assertAlmostEqual(mocked_sleep.call_args[0][0], 1.0, delta=0.3)

    def test_output_store_persists_validation_alias_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            store = PipelineOutputStore.create(
                output_root, "example.com", {"write_artifact_manifest": True}
            )
            summary = {"counts": {"urls": 3}, "validation_results": {"api_key_validation": []}}
            store.persist_outputs(
                summary=summary,
                diff_summary={"artifacts": {}},
                screenshots=[],
                analysis_results={"header_checker": [{"url": "https://example.com"}]},
                merged_findings=[{"title": "demo"}],
            )

            validation_path = store.run_dir / "validation_results.json"
            alias_path = store.run_dir / "custom_validation_results.json"
            manifest_path = store.run_dir / "artifacts.json"

            self.assertTrue(validation_path.exists())
            self.assertTrue(alias_path.exists())
            self.assertEqual(
                validation_path.read_text(encoding="utf-8"), alias_path.read_text(encoding="utf-8")
            )
            self.assertTrue(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
