import unittest

from src.core.logging.pipeline_logging import PROGRESS_PREFIX
from src.pipeline.runner_support import emit_stage_skipped
from src.pipeline.stage_plan import constrain_remaining_stages, export_stage_graph, merge_tool_status


class StagePlanTests(unittest.TestCase):
    def test_nuclei_dropped_when_tool_disabled(self) -> None:
        remaining = ["subdomains", "live_hosts", "urls", "passive_scan", "nuclei", "reporting"]
        planned = constrain_remaining_stages(
            remaining,
            config={"tools": {"nuclei": False}},
        )
        self.assertNotIn("nuclei", planned)
        self.assertIn("subdomains", planned)
        self.assertIn("reporting", planned)

    def test_nuclei_kept_when_selected(self) -> None:
        remaining = ["subdomains", "nuclei", "reporting"]
        planned = constrain_remaining_stages(
            remaining,
            config={"tools": {"nuclei": True}},
            selected_modules=["subfinder", "nuclei"],
        )
        self.assertIn("nuclei", planned)

    def test_nuclei_dropped_when_not_in_selected_modules(self) -> None:
        remaining = ["subdomains", "nuclei", "semgrep", "reporting"]
        planned = constrain_remaining_stages(
            remaining,
            selected_modules=["subfinder", "httpx"],
        )
        self.assertNotIn("nuclei", planned)
        self.assertNotIn("semgrep", planned)
        self.assertEqual(planned, ["subdomains", "reporting"])

    def test_merge_tool_status_disables_unchecked_tools(self) -> None:
        merged = merge_tool_status({"nuclei": True, "httpx": True}, {"tools": {"nuclei": False}})
        self.assertFalse(merged["nuclei"])
        self.assertTrue(merged["httpx"])


class SkipEventTests(unittest.TestCase):
    def test_skip_event_is_a_progress_payload(self) -> None:
        captured: list[tuple[object, ...]] = []

        def fake_emit(stage: str, message: str, percent: int, **fields: object) -> None:
            captured.append((stage, message, percent, fields))

        from src.pipeline import runner_support

        original = runner_support.emit_progress
        runner_support.emit_progress = fake_emit  # type: ignore[assignment]
        try:
            emit_stage_skipped("nuclei", "no live hosts")
        finally:
            runner_support.emit_progress = original  # type: ignore[assignment]

        self.assertEqual(len(captured), 1)
        stage, message, percent, fields = captured[0]
        self.assertEqual(stage, "nuclei")
        self.assertIn("skipped", str(message).lower())
        self.assertEqual(fields.get("status"), "skipped")
        self.assertEqual(fields.get("reason"), "no live hosts")
        self.assertTrue(str(PROGRESS_PREFIX).startswith("PIPELINE_PROGRESS"))
        self.assertFalse(str(message).startswith("[INSTRUMENT]"))


if __name__ == "__main__":
    unittest.main()
