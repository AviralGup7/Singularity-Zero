import unittest

from src.analysis.helpers import decode_candidate_value


class AnalysisHelpersDecodeTests(unittest.TestCase):
    def test_decode_candidate_value_decodes_nested_encoding(self) -> None:
        encoded = "https%253A%252F%252Fexample.com%252Fcb%253Fnext%253D%25252Fhome"

        decoded = decode_candidate_value(encoded)

        self.assertEqual(decoded, "https://example.com/cb?next=/home")

    def test_decode_candidate_value_handles_malformed_sequences(self) -> None:
        malformed = "https%3A%2F%2Fexample.com%2F%ZZ"

        decoded = decode_candidate_value(malformed)

        self.assertEqual(decoded, "https://example.com/%ZZ")


if __name__ == "__main__":
    unittest.main()
