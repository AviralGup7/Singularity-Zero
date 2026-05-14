import io
import unittest
from contextlib import redirect_stdout

from src.api_tests.apitester.api_key_workflows.shared import (
    placement_request_parts,
    print_banner,
    print_section_header,
    print_summary_header,
)


class ApiKeyWorkflowSharedTests(unittest.TestCase):
    def test_placement_request_parts_merges_headers_and_params_without_mutation(self) -> None:
        base_headers = {"User-Agent": "test-agent"}
        placement = {
            "headers": {"Authorization": "Bearer token"},
            "params": {"apikey": "secret"},
        }

        merged_headers, merged_params = placement_request_parts(base_headers, placement)  # type: ignore[arg-type]  # type: ignore[arg-type]

        self.assertEqual(base_headers, {"User-Agent": "test-agent"})
        self.assertEqual(
            merged_headers, {"User-Agent": "test-agent", "Authorization": "Bearer token"}
        )
        self.assertEqual(merged_params, {"apikey": "secret"})

    def test_banner_and_section_helpers_preserve_expected_layout(self) -> None:
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            print_banner("TITLE", ["Line 1", "Line 2"], divider_width=5)
            print_section_header("Section", divider_width=3)
            print_summary_header("Summary", divider_width=4)

        self.assertEqual(
            stdout.getvalue(),
            "TITLE\nLine 1\nLine 2\n=====\n\nSection\n---\n\n====\nSummary\n====\n",
        )


if __name__ == "__main__":
    unittest.main()
