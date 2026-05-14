import unittest

from src.execution.validators.engine_helpers import compare_response_shapes


class ValidationEngineHelperTests(unittest.TestCase):
    def test_compare_response_shapes_uses_response_similarity_match_state(self) -> None:
        original = {"status_code": 200, "body_length": 1024}
        variant = {"status_code": 200, "body_length": 1080}

        state = compare_response_shapes(original, variant)

        self.assertEqual(state, "response_similarity_match")

    def test_compare_response_shapes_detects_potential_idor_on_unauthorized_to_success(
        self,
    ) -> None:
        original = {"status_code": 403, "body_length": 200}
        variant = {"status_code": 200, "body_length": 240}

        state = compare_response_shapes(original, variant)

        self.assertEqual(state, "potential_idor")


if __name__ == "__main__":
    unittest.main()
