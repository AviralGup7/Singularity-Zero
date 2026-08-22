import unittest

from src.dashboard.fastapi.routers.findings.field_map import (
    canonicalize_status,
    map_update_payload,
    project_finding_aliases,
)


class FieldMapTests(unittest.TestCase):
    def test_canonicalize_keeps_unknown_status(self) -> None:
        self.assertEqual(canonicalize_status("accepted"), "accepted")
        self.assertEqual(canonicalize_status("active"), "open")
        self.assertEqual(canonicalize_status(""), "open")
        self.assertEqual(canonicalize_status("needs-review"), "needs-review")

    def test_map_update_payload_maps_camel_and_bulk_delete(self) -> None:
        mapped = map_update_payload(
            {"assignedTo": "ada", "falsePositive": True, "status": "closed"},
            bulk=False,
        )
        self.assertEqual(mapped["assignee"], "ada")
        self.assertTrue(mapped["false_positive"])
        self.assertEqual(mapped["fp_status"], "approved")
        self.assertEqual(mapped["status"], "closed")
        self.assertNotIn("_deleted", mapped)

        tombstone = map_update_payload({"_deleted": True, "ids": ["a"]}, bulk=True)
        self.assertEqual(tombstone, {"_deleted": True})

    def test_project_aliases_does_not_override_explicit_status(self) -> None:
        accepted = project_finding_aliases({"status": "accepted", "false_positive": True})
        self.assertEqual(accepted["status"], "accepted")
        self.assertTrue(accepted["falsePositive"])

        open_fp = project_finding_aliases({"status": "open", "false_positive": True})
        self.assertEqual(open_fp["status"], "false_positive")

    def test_coerce_bool_does_not_treat_false_string_as_true(self) -> None:
        self.assertFalse(coerce_bool("false"))
        self.assertFalse(coerce_bool("0"))
        self.assertTrue(coerce_bool("true"))
        mapped = map_update_payload({"falsePositive": "false"})
        self.assertEqual(mapped.get("false_positive"), False)
        self.assertNotIn("fp_status", mapped)


if __name__ == "__main__":
    unittest.main()
