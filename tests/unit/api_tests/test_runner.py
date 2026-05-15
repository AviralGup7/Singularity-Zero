from unittest.mock import MagicMock

import pytest

from src.api_tests.apitester.api_key_workflows.registry import (
    WORKFLOW_SPECS,
    WORKFLOW_SPECS_BY_KEY,
    ApiKeyWorkflowSpec,
    get_workflow,
    get_workflow_runner,
    list_workflows,
)


class TestApiKeyWorkflowSpec:
    @pytest.mark.unit
    def test_spec_creation(self):
        mock_runner = MagicMock()
        spec = ApiKeyWorkflowSpec(
            key="test",
            label="Test Workflow",
            description="A test workflow",
            runner=mock_runner,
        )
        assert spec.key == "test"
        assert spec.label == "Test Workflow"
        assert spec.description == "A test workflow"
        assert spec.runner is mock_runner

    @pytest.mark.unit
    def test_spec_frozen(self):
        mock_runner = MagicMock()
        spec = ApiKeyWorkflowSpec(
            key="test",
            label="Test",
            description="Test",
            runner=mock_runner,
        )
        with pytest.raises((AttributeError, TypeError)):
            spec.key = "modified"

    @pytest.mark.unit
    def test_spec_equality(self):
        mock_runner = MagicMock()
        spec1 = ApiKeyWorkflowSpec(
            key="test",
            label="Test",
            description="Test",
            runner=mock_runner,
        )
        spec2 = ApiKeyWorkflowSpec(
            key="test",
            label="Test",
            description="Test",
            runner=mock_runner,
        )
        assert spec1 == spec2

    @pytest.mark.unit
    def test_spec_inequality(self):
        mock_runner = MagicMock()
        spec1 = ApiKeyWorkflowSpec(
            key="test1",
            label="Test 1",
            description="Test 1",
            runner=mock_runner,
        )
        spec2 = ApiKeyWorkflowSpec(
            key="test2",
            label="Test 2",
            description="Test 2",
            runner=mock_runner,
        )
        assert spec1 != spec2


class TestWorkflowSpecs:
    @pytest.mark.unit
    def test_workflow_specs_is_tuple(self):
        assert isinstance(WORKFLOW_SPECS, tuple)

    @pytest.mark.unit
    def test_workflow_specs_count(self):
        assert len(WORKFLOW_SPECS) == 4

    @pytest.mark.unit
    def test_all_specs_are_api_key_workflow_spec(self):
        for spec in WORKFLOW_SPECS:
            assert isinstance(spec, ApiKeyWorkflowSpec)

    @pytest.mark.unit
    def test_all_specs_have_unique_keys(self):
        keys = [spec.key for spec in WORKFLOW_SPECS]
        assert len(keys) == len(set(keys))

    @pytest.mark.unit
    def test_all_specs_have_non_empty_labels(self):
        for spec in WORKFLOW_SPECS:
            assert len(spec.label) > 0

    @pytest.mark.unit
    def test_all_specs_have_non_empty_descriptions(self):
        for spec in WORKFLOW_SPECS:
            assert len(spec.description) > 0

    @pytest.mark.unit
    def test_all_specs_have_callable_runners(self):
        for spec in WORKFLOW_SPECS:
            assert callable(spec.runner)

    @pytest.mark.unit
    def test_expected_workflow_keys_exist(self):
        expected_keys = {"advanced", "detailed", "scope", "write_actions"}
        actual_keys = {spec.key for spec in WORKFLOW_SPECS}
        assert expected_keys == actual_keys


class TestWorkflowSpecsByKey:
    @pytest.mark.unit
    def test_is_dict(self):
        assert isinstance(WORKFLOW_SPECS_BY_KEY, dict)

    @pytest.mark.unit
    def test_count_matches_specs(self):
        assert len(WORKFLOW_SPECS_BY_KEY) == len(WORKFLOW_SPECS)

    @pytest.mark.unit
    def test_all_keys_are_strings(self):
        for key in WORKFLOW_SPECS_BY_KEY:
            assert isinstance(key, str)

    @pytest.mark.unit
    def test_all_values_are_specs(self):
        for value in WORKFLOW_SPECS_BY_KEY.values():
            assert isinstance(value, ApiKeyWorkflowSpec)

    @pytest.mark.unit
    def test_key_matches_spec_key(self):
        for key, spec in WORKFLOW_SPECS_BY_KEY.items():
            assert spec.key == key

    @pytest.mark.unit
    def test_advanced_workflow_exists(self):
        assert "advanced" in WORKFLOW_SPECS_BY_KEY

    @pytest.mark.unit
    def test_detailed_workflow_exists(self):
        assert "detailed" in WORKFLOW_SPECS_BY_KEY

    @pytest.mark.unit
    def test_scope_workflow_exists(self):
        assert "scope" in WORKFLOW_SPECS_BY_KEY

    @pytest.mark.unit
    def test_write_actions_workflow_exists(self):
        assert "write_actions" in WORKFLOW_SPECS_BY_KEY


class TestListWorkflows:
    @pytest.mark.unit
    def test_returns_tuple(self):
        result = list_workflows()
        assert isinstance(result, tuple)

    @pytest.mark.unit
    def test_returns_same_as_workflow_specs(self):
        assert list_workflows() is WORKFLOW_SPECS

    @pytest.mark.unit
    def test_correct_length(self):
        assert len(list_workflows()) == 4


class TestGetWorkflow:
    @pytest.mark.unit
    def test_get_advanced_workflow(self):
        spec = get_workflow("advanced")
        assert spec.key == "advanced"
        assert isinstance(spec, ApiKeyWorkflowSpec)

    @pytest.mark.unit
    def test_get_detailed_workflow(self):
        spec = get_workflow("detailed")
        assert spec.key == "detailed"

    @pytest.mark.unit
    def test_get_scope_workflow(self):
        spec = get_workflow("scope")
        assert spec.key == "scope"

    @pytest.mark.unit
    def test_get_write_actions_workflow(self):
        spec = get_workflow("write_actions")
        assert spec.key == "write_actions"

    @pytest.mark.unit
    def test_invalid_key_raises_key_error(self):
        with pytest.raises(KeyError):
            get_workflow("nonexistent")

    @pytest.mark.unit
    def test_empty_string_raises_key_error(self):
        with pytest.raises(KeyError):
            get_workflow("")


class TestGetWorkflowRunner:
    @pytest.mark.unit
    def test_returns_callable_for_advanced(self):
        runner = get_workflow_runner("advanced")
        assert callable(runner)

    @pytest.mark.unit
    def test_returns_callable_for_detailed(self):
        runner = get_workflow_runner("detailed")
        assert callable(runner)

    @pytest.mark.unit
    def test_returns_callable_for_scope(self):
        runner = get_workflow_runner("scope")
        assert callable(runner)

    @pytest.mark.unit
    def test_returns_callable_for_write_actions(self):
        runner = get_workflow_runner("write_actions")
        assert callable(runner)

    @pytest.mark.unit
    def test_invalid_key_raises_key_error(self):
        with pytest.raises(KeyError):
            get_workflow_runner("nonexistent")

    @pytest.mark.unit
    def test_runner_matches_spec_runner(self):
        for key in WORKFLOW_SPECS_BY_KEY:
            runner = get_workflow_runner(key)
            assert runner is WORKFLOW_SPECS_BY_KEY[key].runner
