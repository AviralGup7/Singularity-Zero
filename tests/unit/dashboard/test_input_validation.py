import unittest

from src.dashboard.fastapi.validation import (
    sanitize_path_segment,
    validate_json_payload,
    validate_replay_id,
    validate_run_name,
    validate_target_name,
    validate_url,
)


class ValidateTargetNameTests(unittest.TestCase):
    def test_valid_name(self) -> None:
        self.assertTrue(validate_target_name("example.com"))

    def test_valid_name_with_dashes(self) -> None:
        self.assertTrue(validate_target_name("my-target"))

    def test_valid_name_with_dots(self) -> None:
        self.assertTrue(validate_target_name("api.example.com"))

    def test_rejects_empty(self) -> None:
        self.assertFalse(validate_target_name(""))

    def test_rejects_null_byte(self) -> None:
        self.assertFalse(validate_target_name("foo\x00bar"))

    def test_rejects_path_traversal(self) -> None:
        self.assertFalse(validate_target_name("../etc"))

    def test_rejects_leading_dot(self) -> None:
        self.assertFalse(validate_target_name(".hidden"))

    def test_rejects_spaces(self) -> None:
        self.assertFalse(validate_target_name("foo bar"))

    def test_rejects_control_chars(self) -> None:
        self.assertFalse(validate_target_name("foo\x01bar"))


class ValidateRunNameTests(unittest.TestCase):
    def test_valid_run_name(self) -> None:
        self.assertTrue(validate_run_name("run-2024-01"))

    def test_valid_run_name_with_slash(self) -> None:
        self.assertTrue(validate_run_name("scan/full"))

    def test_rejects_empty(self) -> None:
        self.assertFalse(validate_run_name(""))

    def test_rejects_null_byte(self) -> None:
        self.assertFalse(validate_run_name("run\x00"))

    def test_rejects_path_traversal(self) -> None:
        self.assertFalse(validate_run_name("../run"))


class ValidateReplayIdTests(unittest.TestCase):
    def test_valid_replay_id(self) -> None:
        self.assertTrue(validate_replay_id("abc-123_def"))

    def test_valid_numeric_id(self) -> None:
        self.assertTrue(validate_replay_id("12345"))

    def test_rejects_empty(self) -> None:
        self.assertFalse(validate_replay_id(""))

    def test_rejects_null_byte(self) -> None:
        self.assertFalse(validate_replay_id("id\x00"))

    def test_rejects_path_traversal(self) -> None:
        self.assertFalse(validate_replay_id("../id"))

    def test_rejects_special_chars(self) -> None:
        self.assertFalse(validate_replay_id("id<script>"))


class ValidateUrlTests(unittest.TestCase):
    def test_valid_http_url(self) -> None:
        self.assertTrue(validate_url("http://example.com/path"))

    def test_valid_https_url(self) -> None:
        self.assertTrue(validate_url("https://example.com/path"))

    def test_rejects_empty(self) -> None:
        self.assertFalse(validate_url(""))

    def test_rejects_ftp_scheme(self) -> None:
        self.assertFalse(validate_url("ftp://example.com"))

    def test_rejects_null_byte(self) -> None:
        self.assertFalse(validate_url("http://example.com\x00/path"))

    def test_rejects_path_traversal_in_host(self) -> None:
        self.assertFalse(validate_url("http://../etc/passwd"))

    def test_rejects_no_hostname(self) -> None:
        self.assertFalse(validate_url("http:///path"))


class ValidateJsonPayloadTests(unittest.TestCase):
    def test_valid_json_object(self) -> None:
        result = validate_json_payload(b'{"key": "value"}')
        self.assertIsNotNone(result)
        self.assertEqual(result, {"key": "value"})

    def test_rejects_empty(self) -> None:
        self.assertIsNone(validate_json_payload(b""))

    def test_rejects_null_bytes(self) -> None:
        self.assertIsNone(validate_json_payload(b'{"key": "val\x00ue"}'))

    def test_rejects_json_array(self) -> None:
        self.assertIsNone(validate_json_payload(b"[1,2,3]"))

    def test_rejects_invalid_json(self) -> None:
        self.assertIsNone(validate_json_payload(b"{invalid}"))

    def test_rejects_oversized_payload(self) -> None:
        large = b'{"key": "' + b"x" * 2_000_000 + b'"}'
        self.assertIsNone(validate_json_payload(large))


class SanitizePathSegmentTests(unittest.TestCase):
    def test_removes_null_bytes(self) -> None:
        self.assertEqual(sanitize_path_segment("foo\x00bar"), "foobar")

    def test_removes_traversal(self) -> None:
        self.assertEqual(sanitize_path_segment("../etc"), "etc")

    def test_removes_dot_segments(self) -> None:
        self.assertEqual(sanitize_path_segment("./foo/./bar"), "foo/bar")

    def test_backslash_to_slash(self) -> None:
        self.assertEqual(sanitize_path_segment("foo\\bar"), "foo/bar")

    def test_removes_control_chars(self) -> None:
        self.assertEqual(sanitize_path_segment("foo\x01bar"), "foobar")


if __name__ == "__main__":
    unittest.main()
