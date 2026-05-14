import unittest

from src.analysis.response.mutations import _variant_diff_summary


class StructuredResponseDiffTests(unittest.TestCase):
    def test_structured_diff_detects_field_changes(self) -> None:
        original = {
            "status_code": 200,
            "content_type": "application/json",
            "body_text": '{"profile":{"name":"alice","email":"a@example.com"},"roles":["user"]}',
            "headers": {},
        }
        mutated = {
            "status_code": 200,
            "content_type": "application/json",
            "body_text": '{"profile":{"name":"alice","email":"b@example.com","phone":"123"},"roles":["admin"]}',
            "headers": {},
        }

        diff = _variant_diff_summary(original, mutated)

        self.assertTrue(diff["structured_diff_available"])
        self.assertIn("profile.phone", diff["new_fields"])
        changed_fields = {item["field"] for item in diff["changed_fields"]}
        self.assertIn("profile.email", changed_fields)
        self.assertIn("roles[0]", changed_fields)

    def test_structured_diff_ignores_noise_fields(self) -> None:
        original = {
            "status_code": 200,
            "content_type": "application/json",
            "body_text": '{"id":1,"updated_at":"2026-01-01T00:00:00Z","profile":{"name":"alice"}}',
            "headers": {},
        }
        mutated = {
            "status_code": 200,
            "content_type": "application/json",
            "body_text": '{"id":2,"updated_at":"2026-01-01T00:00:10Z","profile":{"name":"alice"}}',
            "headers": {},
        }

        diff = _variant_diff_summary(original, mutated)

        self.assertTrue(diff["structured_diff_available"])
        self.assertEqual(diff["new_fields"], [])
        self.assertEqual(diff["missing_fields"], [])
        self.assertEqual(diff["changed_fields"], [])

    def test_raw_fallback_when_json_parse_fails(self) -> None:
        original = {
            "status_code": 200,
            "content_type": "text/html",
            "body_text": "<html>alpha</html>",
            "headers": {},
        }
        mutated = {
            "status_code": 200,
            "content_type": "text/html",
            "body_text": "<html>beta</html>",
            "headers": {},
        }

        diff = _variant_diff_summary(original, mutated)

        self.assertFalse(diff["structured_diff_available"])
        self.assertIn("body_similarity", diff)
        self.assertIn("changed", diff)


if __name__ == "__main__":
    unittest.main()
