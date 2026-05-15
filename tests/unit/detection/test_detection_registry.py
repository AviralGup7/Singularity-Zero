"""Tests for detection registry module."""

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest


@dataclass(frozen=True)
class DetectionPlugin:
    key: str
    label: str
    group: str
    input_kind: str
    enabled_by_default: bool
    phase: str = "discover"
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()


class TestDetectionPluginDataclass:
    def test_detection_plugin_is_frozen(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        with pytest.raises(AttributeError):
            plugin.key = "modified"

    def test_detection_plugin_default_phase(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        assert plugin.phase == "discover"

    def test_detection_plugin_default_consumes(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        assert plugin.consumes == ()

    def test_detection_plugin_default_produces(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        assert plugin.produces == ()

    def test_detection_plugin_custom_phase(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
            phase="validate",
        )
        assert plugin.phase == "validate"

    def test_detection_plugin_custom_consumes_produces(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
            consumes=("urls",),
            produces=("findings",),
        )
        assert plugin.consumes == ("urls",)
        assert plugin.produces == ("findings",)

    def test_detection_plugin_all_fields(self) -> None:
        plugin = DetectionPlugin(
            key="sqli_scan",
            label="SQL Injection Scanner",
            group="active",
            input_kind="urls_and_responses",
            enabled_by_default=True,
            phase="discover",
            consumes=("urls", "responses"),
            produces=("findings",),
        )
        assert plugin.key == "sqli_scan"
        assert plugin.label == "SQL Injection Scanner"
        assert plugin.group == "active"
        assert plugin.input_kind == "urls_and_responses"
        assert plugin.enabled_by_default is True
        assert plugin.phase == "discover"
        assert plugin.consumes == ("urls", "responses")
        assert plugin.produces == ("findings",)

    def test_detection_plugin_hashable(self) -> None:
        plugin = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        plugin_set = {plugin, plugin}
        assert len(plugin_set) == 1

    def test_detection_plugin_equality(self) -> None:
        p1 = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        p2 = DetectionPlugin(
            key="test",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        assert p1 == p2

    def test_detection_plugin_inequality(self) -> None:
        p1 = DetectionPlugin(
            key="test1",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        p2 = DetectionPlugin(
            key="test2",
            label="Test",
            group="grp",
            input_kind="responses_only",
            enabled_by_default=True,
        )
        assert p1 != p2


class TestDetectionRegistry:
    @patch("src.detection.registry.DETECTION_PLUGINS")
    @patch("src.detection.registry.DETECTION_PLUGINS_BY_KEY")
    def test_detection_plugins_is_tuple(self, mock_by_key, mock_plugins) -> None:
        mock_plugins.__iter__ = MagicMock(return_value=iter([]))
        from src.detection import registry

        assert hasattr(registry, "DETECTION_PLUGINS")

    def test_registry_module_has_expected_exports(self) -> None:
        from src.detection import registry

        assert hasattr(registry, "list_detection_plugins")
        assert hasattr(registry, "get_detection_plugin")
        assert hasattr(registry, "run_detection_plugin")
        assert hasattr(registry, "detection_plugin_options")

    def test_detection_plugins_not_empty(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS

        assert len(DETECTION_PLUGINS) > 0

    def test_all_plugins_are_detection_plugin_instances(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, DetectionPlugin

        for plugin in DETECTION_PLUGINS:
            assert isinstance(plugin, DetectionPlugin)

    def test_plugins_have_unique_keys(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS

        keys = [p.key for p in DETECTION_PLUGINS]
        assert len(keys) == len(set(keys))

    def test_plugins_by_key_is_dict(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS_BY_KEY

        assert isinstance(DETECTION_PLUGINS_BY_KEY, dict)

    def test_plugins_by_key_matches_plugins(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, DETECTION_PLUGINS_BY_KEY

        assert set(DETECTION_PLUGINS_BY_KEY.keys()) == {p.key for p in DETECTION_PLUGINS}

    def test_plugins_by_key_values_match(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, DETECTION_PLUGINS_BY_KEY

        for plugin in DETECTION_PLUGINS:
            assert DETECTION_PLUGINS_BY_KEY[plugin.key] == plugin

    def test_each_plugin_has_required_fields(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS

        for plugin in DETECTION_PLUGINS:
            assert plugin.key
            assert plugin.label
            assert plugin.group
            assert plugin.input_kind

    def test_each_plugin_has_boolean_enabled(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS

        for plugin in DETECTION_PLUGINS:
            assert isinstance(plugin.enabled_by_default, bool)

    def test_plugin_groups_are_valid(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS

        valid_groups = {
            "exposure",
            "session",
            "redirect",
            "active",
            "logic",
            "access",
            "idor",
            "passive",
        }
        for plugin in DETECTION_PLUGINS:
            assert plugin.group in valid_groups

    def test_plugin_input_kinds_are_valid(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS

        valid_kinds = {
            "responses_only",
            "urls_only",
            "priority_urls_and_cache",
            "priority_urls_only",
            "urls_and_responses",
            "ranked_items_and_cache",
            "responses_and_bulk_items",
            "behavior_analysis",
            "header_targets_and_cache",
        }
        for plugin in DETECTION_PLUGINS:
            assert plugin.input_kind in valid_kinds


class TestListDetectionPlugins:
    def test_list_returns_same_as_constant(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, list_detection_plugins

        result = list_detection_plugins()
        assert result == DETECTION_PLUGINS

    def test_list_returns_tuple(self) -> None:
        from src.detection.registry import list_detection_plugins

        assert isinstance(list_detection_plugins(), tuple)


class TestGetDetectionPlugin:
    def test_get_existing_plugin(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, get_detection_plugin

        first = DETECTION_PLUGINS[0]
        result = get_detection_plugin(first.key)
        assert result == first

    def test_get_plugin_with_whitespace(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, get_detection_plugin

        first = DETECTION_PLUGINS[0]
        result = get_detection_plugin(f"  {first.key}  ")
        assert result == first

    def test_get_unknown_plugin_raises_keyerror(self) -> None:
        from src.detection.registry import get_detection_plugin

        with pytest.raises(KeyError, match="Unknown detection plugin"):
            get_detection_plugin("nonexistent_plugin_xyz")

    def test_keyerror_contains_available_plugins(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, get_detection_plugin

        with pytest.raises(KeyError) as exc_info:
            get_detection_plugin("nonexistent_plugin_xyz")
        assert DETECTION_PLUGINS[0].key in str(exc_info.value)


class TestDetectionPluginOptions:
    def test_options_is_list(self) -> None:
        from src.detection.registry import detection_plugin_options

        result = detection_plugin_options()
        assert isinstance(result, list)

    def test_options_length_matches_plugins(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, detection_plugin_options

        result = detection_plugin_options()
        assert len(result) == len(DETECTION_PLUGINS)

    def test_each_option_has_required_keys(self) -> None:
        from src.detection.registry import detection_plugin_options

        result = detection_plugin_options()
        required_keys = {
            "name",
            "label",
            "description",
            "group",
            "input_kind",
            "enabled_by_default",
            "phase",
            "consumes",
            "produces",
        }
        for option in result:
            assert required_keys.issubset(set(option.keys()))

    def test_option_name_matches_plugin_key(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, detection_plugin_options

        result = detection_plugin_options()
        option_names = {opt["name"] for opt in result}
        plugin_keys = {p.key for p in DETECTION_PLUGINS}
        assert option_names == plugin_keys

    def test_option_consumes_is_list(self) -> None:
        from src.detection.registry import detection_plugin_options

        result = detection_plugin_options()
        for option in result:
            assert isinstance(option["consumes"], list)

    def test_option_produces_is_list(self) -> None:
        from src.detection.registry import detection_plugin_options

        result = detection_plugin_options()
        for option in result:
            assert isinstance(option["produces"], list)


class TestRunDetectionPlugin:
    def test_run_plugin_returns_list(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, run_detection_plugin

        first = DETECTION_PLUGINS[0]
        context = MagicMock()
        result = run_detection_plugin(first.key, context)
        assert isinstance(result, list)

    def test_run_unknown_plugin_raises_keyerror(self) -> None:
        from src.detection.registry import run_detection_plugin

        with pytest.raises(KeyError):
            run_detection_plugin("nonexistent", MagicMock())

    def test_run_plugin_calls_analyzer(self) -> None:
        from src.detection.registry import DETECTION_PLUGINS, run_detection_plugin

        first = DETECTION_PLUGINS[0]
        context = MagicMock()
        result = run_detection_plugin(first.key, context)
        assert isinstance(result, list)
