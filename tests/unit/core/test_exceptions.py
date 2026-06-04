"""Unit tests for src.core.exceptions hierarchy."""

import unittest

import pytest

from src.core.exceptions import (
    AuthError,
    CacheError,
    ConfigError,
    ExternalToolError,
    FindingError,
    PipelineError,
    ReplayError,
    ScopeViolationError,
    StageError,
)


@pytest.mark.unit
class TestPipelineError(unittest.TestCase):
    def test_message_stored(self) -> None:
        exc = PipelineError("boom")
        self.assertEqual(exc.message, "boom")
        self.assertEqual(str(exc), "boom")

    def test_default_details_empty_dict(self) -> None:
        exc = PipelineError("boom")
        self.assertEqual(exc.details, {})

    def test_explicit_details_preserved(self) -> None:
        exc = PipelineError("boom", details={"k": "v"})
        self.assertEqual(exc.details, {"k": "v"})

    def test_subclass_of_exception(self) -> None:
        self.assertTrue(issubclass(PipelineError, Exception))

    def test_can_be_raised_and_caught(self) -> None:
        with self.assertRaises(PipelineError):
            raise PipelineError("test error")

    def test_args_attribute(self) -> None:
        exc = PipelineError("boom")
        self.assertEqual(exc.args, ("boom",))


@pytest.mark.unit
class TestConfigErrorAndChildren(unittest.TestCase):
    def test_config_error_inherits_pipeline_error(self) -> None:
        self.assertTrue(issubclass(ConfigError, PipelineError))

    def test_finding_error_inherits_pipeline_error(self) -> None:
        self.assertTrue(issubclass(FindingError, PipelineError))

    def test_replay_error_inherits_pipeline_error(self) -> None:
        self.assertTrue(issubclass(ReplayError, PipelineError))

    def test_auth_error_inherits_pipeline_error(self) -> None:
        self.assertTrue(issubclass(AuthError, PipelineError))

    def test_cache_error_inherits_pipeline_error(self) -> None:
        self.assertTrue(issubclass(CacheError, PipelineError))

    def test_can_raise_and_catch_as_pipeline_error(self) -> None:
        with self.assertRaises(PipelineError):
            raise ConfigError("config bad")

    def test_all_subclasses_can_carry_details(self) -> None:
        for cls in (ConfigError, FindingError, ReplayError, AuthError, CacheError):
            exc = cls("msg", details={"k": "v"})
            self.assertEqual(exc.details, {"k": "v"})


@pytest.mark.unit
class TestStageError(unittest.TestCase):
    def test_records_stage_name(self) -> None:
        exc = StageError("failed", stage="recon")
        self.assertEqual(exc.stage, "recon")

    def test_stage_optional(self) -> None:
        exc = StageError("failed")
        self.assertIsNone(exc.stage)

    def test_message_propagates(self) -> None:
        exc = StageError("failed", stage="x")
        self.assertEqual(str(exc), "failed")

    def test_details_optional(self) -> None:
        exc = StageError("failed")
        self.assertEqual(exc.details, {})

    def test_details_with_stage(self) -> None:
        exc = StageError("failed", stage="x", details={"k": "v"})
        self.assertEqual(exc.details, {"k": "v"})
        self.assertEqual(exc.stage, "x")


@pytest.mark.unit
class TestExternalToolError(unittest.TestCase):
    def test_tracks_tool_name(self) -> None:
        exc = ExternalToolError("crashed", tool="nuclei")
        self.assertEqual(exc.tool, "nuclei")

    def test_tracks_exit_code(self) -> None:
        exc = ExternalToolError("crashed", tool="nuclei", exit_code=139)
        self.assertEqual(exc.exit_code, 139)

    def test_tool_and_exit_code_optional(self) -> None:
        exc = ExternalToolError("crashed")
        self.assertIsNone(exc.tool)
        self.assertIsNone(exc.exit_code)

    def test_message_propagates(self) -> None:
        exc = ExternalToolError("crashed")
        self.assertEqual(str(exc), "crashed")

    def test_details_with_tool(self) -> None:
        exc = ExternalToolError("crashed", tool="nuclei", details={"k": "v"})
        self.assertEqual(exc.details, {"k": "v"})


@pytest.mark.unit
class TestScopeViolationError(unittest.TestCase):
    def test_target_url_recorded(self) -> None:
        exc = ScopeViolationError("oops", target_url="https://evil.com/")
        self.assertEqual(exc.target_url, "https://evil.com/")

    def test_reason_recorded(self) -> None:
        exc = ScopeViolationError("oops", reason="external host")
        self.assertEqual(exc.reason, "external host")

    def test_scope_hosts_defaults_to_empty_list(self) -> None:
        exc = ScopeViolationError("oops")
        self.assertEqual(exc.scope_hosts, [])

    def test_scope_hosts_preserved(self) -> None:
        exc = ScopeViolationError("oops", scope_hosts=["a.com", "b.com"])
        self.assertEqual(exc.scope_hosts, ["a.com", "b.com"])

    def test_inherits_pipeline_error(self) -> None:
        self.assertTrue(issubclass(ScopeViolationError, PipelineError))

    def test_none_target_url_accepted(self) -> None:
        exc = ScopeViolationError("oops")
        self.assertIsNone(exc.target_url)

    def test_details_preserved(self) -> None:
        exc = ScopeViolationError("oops", details={"k": "v"})
        self.assertEqual(exc.details, {"k": "v"})


if __name__ == "__main__":
    unittest.main()
