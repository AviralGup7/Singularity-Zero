import unittest

from src.core.utils.stderr_classification import classify_stderr_lines


class StderrClassificationTests(unittest.TestCase):
    def test_python_warning_header_is_warning_but_source_context_is_not(self) -> None:
        classification = classify_stderr_lines(
            [
                (
                    r"D:\repo\.venv\Lib\site-packages\urllib3\connectionpool.py:1097: "
                    "InsecureRequestWarning: Unverified HTTPS request"
                ),
                "  warnings.warn(",
            ]
        )

        self.assertEqual(classification.warning_count, 1)
        self.assertEqual(
            classification.warnings,
            [
                (
                    r"D:\repo\.venv\Lib\site-packages\urllib3\connectionpool.py:1097: "
                    "InsecureRequestWarning: Unverified HTTPS request"
                )
            ],
        )
        self.assertEqual(classification.best_warning_line, classification.warnings[-1])
        self.assertNotIn("warnings.warn(", classification.nonfatal_lines)

    def test_other_stderr_text_does_not_become_best_warning_line(self) -> None:
        classification = classify_stderr_lines(
            [
                "Access control: 175 high/critical bypass findings detected",
                "Nuclei not on PATH, skipping active scanning stage",
            ]
        )

        self.assertEqual(classification.warning_count, 0)
        self.assertFalse(classification.has_fatal_signals)
        self.assertEqual(classification.best_warning_line, "")

    def test_unprefixed_timeout_is_preserved_as_timeout_event_not_fatal(self) -> None:
        classification = classify_stderr_lines(["Probe 'auth_bypass' timed out after 180.0s"])

        self.assertEqual(classification.warning_count, 0)
        self.assertFalse(classification.has_fatal_signals)
        self.assertEqual(
            classification.timeout_events, ["Probe 'auth_bypass' timed out after 180.0s"]
        )
        self.assertEqual(
            classification.best_warning_line, "Probe 'auth_bypass' timed out after 180.0s"
        )

    def test_timeout_events_are_preserved_even_when_fatal_signals_exist(self) -> None:
        classification = classify_stderr_lines(
            [
                "ERROR: Critical recon stage failed (urls, required_provider_failure): provider hard failure",
                "Provider archive source timed out after 120 seconds",
            ]
        )

        self.assertTrue(classification.has_fatal_signals)
        self.assertEqual(classification.fatal_signal_count, 1)
        self.assertIn(
            "Provider archive source timed out after 120 seconds",
            classification.timeout_events,
        )


if __name__ == "__main__":
    unittest.main()
