"""Tests for decision attack selection module."""

from src.decision.attack_selection import (
    DEFAULT_SELECTOR_CONFIG,
    select_validation_actions,
)


class TestAttackValidationSelector:
    def test_default_selector_config_is_valid(self):
        assert isinstance(DEFAULT_SELECTOR_CONFIG, dict)
        assert "planner" in DEFAULT_SELECTOR_CONFIG
        assert "actions" in DEFAULT_SELECTOR_CONFIG
        assert DEFAULT_SELECTOR_CONFIG["planner"]["planner_enabled"] is True

    def test_default_selector_config_has_expected_actions(self):
        actions = DEFAULT_SELECTOR_CONFIG["actions"]
        expected_actions = {
            "ssrf_callback_probe",
            "open_redirect_probe",
            "token_replay_check",
            "idor_identifier_probe",
            "auth_boundary_probe",
            "passive_review",
        }
        assert set(actions.keys()) == expected_actions

    def test_default_selector_config_action_structure(self):
        for name, spec in DEFAULT_SELECTOR_CONFIG["actions"].items():
            assert "enabled" in spec
            assert "base_score" in spec
            assert "requires_in_scope" in spec
            assert "reasons" in spec
            assert isinstance(spec["reasons"], list)

    def test_select_validation_actions_returns_list(self):
        result = select_validation_actions(
            url="https://example.com/api/v1/users?id=123",
            params=["id"],
            signals=["identifier_access"],
            scope_hosts={"example.com"},
        )
        assert isinstance(result, list)

    def test_select_validation_actions_with_ssrf_params(self):
        result = select_validation_actions(
            url="https://example.com/fetch?url=https://internal",
            params=["url"],
            signals=["internal_host_reference"],
            scope_hosts={"example.com"},
        )
        assert len(result) > 0
        actions = [item["action"] for item in result]
        assert "ssrf_callback_probe" in actions

    def test_select_validation_actions_with_redirect_params(self):
        result = select_validation_actions(
            url="https://example.com/redirect?next=https://evil.com",
            params=["next"],
            signals=["cross_host_target"],
            scope_hosts={"example.com"},
        )
        actions = [item["action"] for item in result]
        assert "open_redirect_probe" in actions

    def test_select_validation_actions_with_token_params(self):
        result = select_validation_actions(
            url="https://example.com/auth?token=abc123",
            params=["token"],
            signals=["jwt_like_token"],
            scope_hosts={"example.com"},
        )
        actions = [item["action"] for item in result]
        assert "token_replay_check" in actions

    def test_select_validation_actions_with_idor_params(self):
        result = select_validation_actions(
            url="https://example.com/api/users?user_id=42",
            params=["user_id"],
            signals=["identifier_access"],
            scope_hosts={"example.com"},
        )
        actions = [item["action"] for item in result]
        assert "idor_identifier_probe" in actions

    def test_select_validation_actions_sorted_by_score(self):
        result = select_validation_actions(
            url="https://example.com/api?user_id=1&url=http://x",
            params=["user_id", "url"],
            signals=["internal_host_reference", "identifier_access"],
            scope_hosts={"example.com"},
        )
        scores = [item["score"] for item in result]
        assert scores == sorted(scores, reverse=True)

    def test_select_validation_actions_empty_params(self):
        result = select_validation_actions(
            url="https://example.com/page",
            params=[],
            signals=[],
            scope_hosts={"example.com"},
        )
        assert isinstance(result, list)

    def test_select_validation_actions_none_params(self):
        result = select_validation_actions(
            url="https://example.com/page",
            params=None,
            signals=None,
            scope_hosts={"example.com"},
        )
        assert isinstance(result, list)

    def test_select_validation_actions_out_of_scope(self):
        result = select_validation_actions(
            url="https://evil.com/page",
            params=["url"],
            signals=["internal_host_reference"],
            scope_hosts={"example.com"},
        )
        actions = [item["action"] for item in result]
        for action in actions:
            spec = DEFAULT_SELECTOR_CONFIG["actions"].get(action, {})
            if spec.get("requires_in_scope", True):
                assert action == "passive_review" or not spec["requires_in_scope"]

    def test_select_validation_actions_custom_config(self):
        custom_config = {
            "actions": {
                "ssrf_callback_probe": {"enabled": False},
            }
        }
        result = select_validation_actions(
            url="https://example.com/fetch?url=http://x",
            params=["url"],
            signals=["internal_host_reference"],
            scope_hosts={"example.com"},
            config=custom_config,
        )
        actions = [item["action"] for item in result]
        assert "ssrf_callback_probe" not in actions

    def test_select_validation_actions_result_has_required_fields(self):
        result = select_validation_actions(
            url="https://example.com/api?id=1",
            params=["id"],
            signals=[],
            scope_hosts={"example.com"},
        )
        for item in result:
            assert "action" in item
            assert "score" in item
            assert "reason" in item

    def test_select_validation_actions_auth_flow_url(self):
        result = select_validation_actions(
            url="https://example.com/oauth/callback?code=abc",
            params=["code"],
            signals=["auth_flow_endpoint", "oauth_redirect_sink"],
            scope_hosts={"example.com"},
        )
        actions = [item["action"] for item in result]
        assert "auth_boundary_probe" in actions

    def test_select_validation_actions_compound_rule_tenant_chain(self):
        result = select_validation_actions(
            url="https://example.com/api/tenant/123/users?user_id=42",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        assert len(result) > 0
        has_plan = any("plan" in item for item in result)
        assert has_plan

    def test_select_validation_actions_result_reason_not_empty(self):
        result = select_validation_actions(
            url="https://example.com/api?id=1",
            params=["id"],
            signals=[],
            scope_hosts={"example.com"},
        )
        for item in result:
            assert item["reason"], f"Empty reason for action {item['action']}"

    def test_select_validation_actions_with_set_params(self):
        result = select_validation_actions(
            url="https://example.com/api",
            params={"url", "callback"},
            signals={"internal_host_reference"},
            scope_hosts={"example.com"},
        )
        assert isinstance(result, list)
        actions = [item["action"] for item in result]
        assert "ssrf_callback_probe" in actions

    def test_select_validation_actions_with_tuple_params(self):
        result = select_validation_actions(
            url="https://example.com/api",
            params=("url", "callback"),
            signals=("internal_host_reference",),
            scope_hosts={"example.com"},
        )
        assert isinstance(result, list)


class TestAttackCandidateRanking:
    def test_actions_ranked_by_score_descending(self):
        result = select_validation_actions(
            url="https://example.com/api?user_id=1&url=http://x&token=abc",
            params=["user_id", "url", "token"],
            signals=["internal_host_reference", "jwt_like_token", "identifier_access"],
            scope_hosts={"example.com"},
        )
        for i in range(len(result) - 1):
            assert result[i]["score"] >= result[i + 1]["score"]

    def test_higher_score_for_matching_signals(self):
        result_with_signals = select_validation_actions(
            url="https://example.com/fetch?url=http://x",
            params=["url"],
            signals=["internal_host_reference"],
            scope_hosts={"example.com"},
        )
        result_no_signals = select_validation_actions(
            url="https://example.com/fetch?url=http://x",
            params=["url"],
            signals=[],
            scope_hosts={"example.com"},
        )
        ssrf_with = next(
            (i["score"] for i in result_with_signals if i["action"] == "ssrf_callback_probe"), 0
        )
        ssrf_without = next(
            (i["score"] for i in result_no_signals if i["action"] == "ssrf_callback_probe"), 0
        )
        assert ssrf_with > ssrf_without


class TestAttackChainSelection:
    def test_compound_rule_creates_plan(self):
        result = select_validation_actions(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        planned = [item for item in result if "plan" in item]
        assert len(planned) > 0

    def test_plan_has_rule_id(self):
        result = select_validation_actions(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        planned = [item for item in result if "plan" in item]
        for item in planned:
            assert "rule_id" in item["plan"]

    def test_plan_has_steps(self):
        result = select_validation_actions(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        planned = [item for item in result if "plan" in item]
        for item in planned:
            assert "steps" in item["plan"]
            assert isinstance(item["plan"]["steps"], list)

    def test_plan_has_required_sessions(self):
        result = select_validation_actions(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        planned = [item for item in result if "plan" in item]
        for item in planned:
            assert "required_sessions" in item["plan"]

    def test_plan_has_stop_conditions(self):
        result = select_validation_actions(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint", "identifier_access"],
            scope_hosts={"example.com"},
        )
        planned = [item for item in result if "plan" in item]
        for item in planned:
            assert "stop_conditions" in item["plan"]

    def test_planner_disabled_returns_base_ranked(self):
        config = {"planner": {"planner_enabled": False}}
        result = select_validation_actions(
            url="https://example.com/api/tenant/1/users?user_id=1",
            params=["user_id", "tenant_id"],
            signals=["auth_flow_endpoint"],
            scope_hosts={"example.com"},
            config=config,
        )
        planned = [item for item in result if "plan" in item]
        assert len(planned) == 0

    def test_redirect_token_chain_selected(self):
        result = select_validation_actions(
            url="https://example.com/oauth/callback?redirect=https://evil.com&token=abc",
            params=["redirect", "token"],
            signals=["auth_flow_endpoint", "cross_host_target", "jwt_like_token"],
            scope_hosts={"example.com"},
        )
        planned = [item for item in result if "plan" in item]
        assert len(planned) > 0
