import unittest

from src.decision.authorization import ExecutionAuthorizer, ScopeAuthorizationError
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import ActionSpec, ExecutionRequest, ScopeToken, TargetSpec


class TestHuntBudgetReservationIntegration(unittest.TestCase):
    def test_authorization_reserves_budget_and_rejects_on_exhaustion(self):
        budget = HuntBudget(max_requests=2)
        enforcer = HuntBudgetEnforcer(budget=budget)
        authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)

        req1 = ExecutionRequest(
            request_id="req_1",
            tenant_id="default",
            target=TargetSpec(host="example.com", path="/item1"),
            stage="probing",
            actions=(ActionSpec(action_id="a1", action_type="probe", tool_or_detector="p1"),),
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("example.com",)),
        )

        req2 = ExecutionRequest(
            request_id="req_2",
            tenant_id="default",
            target=TargetSpec(host="example.com", path="/item2"),
            stage="probing",
            actions=(ActionSpec(action_id="a2", action_type="probe", tool_or_detector="p2"),),
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("example.com",)),
        )

        req3 = ExecutionRequest(
            request_id="req_3",
            tenant_id="default",
            target=TargetSpec(host="example.com", path="/item3"),
            stage="probing",
            actions=(ActionSpec(action_id="a3", action_type="probe", tool_or_detector="p3"),),
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("example.com",)),
        )

        # 1. Authorize req1 and req2 -> succeeds and reserves 2 requests
        tkt1 = authorizer.authorize(req1)
        self.assertIsNotNone(tkt1)
        self.assertEqual(enforcer.reserved_requests, 1)

        tkt2 = authorizer.authorize(req2)
        self.assertIsNotNone(tkt2)
        self.assertEqual(enforcer.reserved_requests, 2)
        self.assertEqual(enforcer.available_requests, 0)

        # 2. Authorize req3 -> fails because capacity is reserved
        with self.assertRaises(ScopeAuthorizationError) as ctx:
            authorizer.authorize(req3)
        self.assertIn("budget capacity exhausted", str(ctx.exception))

        # 3. Release req1 reservation (e.g. on dispatch failure)
        enforcer.release_requests(1)
        self.assertEqual(enforcer.reserved_requests, 1)
        self.assertEqual(enforcer.available_requests, 1)

        # 4. Now req3 authorization succeeds
        tkt3 = authorizer.authorize(req3)
        self.assertIsNotNone(tkt3)
        self.assertEqual(enforcer.reserved_requests, 2)

        # 5. Commit req2 and req3 upon ingestion
        enforcer.commit_requests(2)
        self.assertEqual(enforcer.reserved_requests, 0)
        self.assertEqual(enforcer.consumed_requests, 2)
