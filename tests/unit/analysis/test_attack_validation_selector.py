import unittest

from src.decision.attack_selection.selector import select_validation_actions


class AttackValidationSelectorTests(unittest.TestCase):
    def test_ranks_actions_using_param_and_signal_hints(self) -> None:
        actions = select_validation_actions(
            url="https://app.example.com/fetch?url=http://169.254.169.254&token=abc",
            params=["url", "token"],
            signals=["internal_host_reference:url", "jwt_like_token"],
            scope_hosts={"app.example.com"},
        )
        self.assertTrue(actions)
        self.assertEqual(actions[0]["action"], "ssrf_callback_probe")
        action_names = [item["action"] for item in actions]
        self.assertIn("token_replay_check", action_names)

    def test_scope_rules_filter_active_actions(self) -> None:
        actions = select_validation_actions(
            url="https://out.example.net/continue?next=https://evil.tld",
            params=["next"],
            signals=["cross_host_target"],
            scope_hosts={"in-scope.example.com"},
        )
        self.assertEqual([item["action"] for item in actions], ["passive_review"])

    def test_config_can_disable_action(self) -> None:
        actions = select_validation_actions(
            url="https://app.example.com/login?next=https://ext.example.net",
            params=["next"],
            signals=["cross_host_target"],
            scope_hosts={"app.example.com"},
            config={"actions": {"open_redirect_probe": {"enabled": False}}},
        )
        self.assertNotIn("open_redirect_probe", [item["action"] for item in actions])

    def test_emits_compound_plan_for_chained_prerequisites(self) -> None:
        actions = select_validation_actions(
            url="https://app.example.com/oauth/callback?tenant_id=t1&id=9&next=https://ext.example.net&token=abc",
            params=["tenant_id", "id", "next", "token"],
            signals=[
                "auth_flow_endpoint",
                "cross_host_target",
                "jwt_like_token",
                "identifier_candidate",
            ],
            scope_hosts={"app.example.com"},
        )
        open_redirect = next(item for item in actions if item["action"] == "open_redirect_probe")
        self.assertIn("plan", open_redirect)
        plan = open_redirect["plan"]
        self.assertIn("required_sessions", plan)
        self.assertIn("stop_conditions", plan)
        self.assertTrue(plan["steps"])
        self.assertGreaterEqual(len(plan["steps"]), 2)

    def test_legacy_fallback_remains_when_chain_facts_absent(self) -> None:
        actions = select_validation_actions(
            url="https://app.example.com/profile",
            params=["lang"],
            signals=["anomaly_low_confidence"],
            scope_hosts={"app.example.com"},
        )
        self.assertTrue(actions)
        self.assertTrue(all("plan" not in item for item in actions))
        self.assertEqual(actions[-1]["action"], "passive_review")


if __name__ == "__main__":
    unittest.main()
