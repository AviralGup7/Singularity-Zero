import time
import unittest
from dataclasses import FrozenInstanceError

from src.core.contracts.execution_request import (
    ExecutionRequestProtocol,
    ExecutionResultProtocol,
)
from src.decision.authorization import (
    AuthorizedExecutionTicket,
    ExecutionAuthorizer,
    ScopeAuthorizationError,
)
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import (
    ActionSpec,
    ExecutionRequest,
    ExecutionResult,
    Finding,
    ResourceLimits,
    ScopeToken,
    TargetSpec,
)
from src.execution.request_executor import ExecutionRequestWorker


class TestExecutionRequestModels(unittest.TestCase):
    def test_target_spec(self):
        target = TargetSpec(host="api.example.com", port=8443, scheme="https", path="/v1/users")
        assert target.url == "https://api.example.com:8443/v1/users"
        d = target.to_dict()
        assert d["host"] == "api.example.com"
        assert d["url"] == "https://api.example.com:8443/v1/users"

        reconstructed = TargetSpec.from_dict(d)
        assert reconstructed.host == target.host
        assert reconstructed.port == target.port

        # Parse string
        from_str = TargetSpec.from_mapping("https://example.org:9000/test")
        self.assertEqual(from_str.host, "example.org")
        self.assertEqual(from_str.port, 9000)
        self.assertEqual(from_str.path, "/test")

    def test_action_spec_immutability(self):
        action = ActionSpec(
            action_id="act_1",
            action_type="probe",
            tool_or_detector="sqli_detector",
            payload=(("param", "id"), ("vector", "' OR 1=1--")),
        )
        with self.assertRaises(FrozenInstanceError):
            action.priority = 200  # type: ignore[misc]

        d = action.to_dict()
        self.assertEqual(d["action_id"], "act_1")
        self.assertEqual(d["payload"]["param"], "id")

        reconstructed = ActionSpec.from_dict(d)
        self.assertEqual(reconstructed.action_id, "act_1")
        self.assertEqual(dict(reconstructed.payload)["vector"], "' OR 1=1--")

    def test_resource_limits_and_scope_token(self):
        limits = ResourceLimits(timeout_seconds=60.0, max_memory_mb=256)
        self.assertEqual(limits.timeout_seconds, 60.0)
        self.assertEqual(limits.max_memory_mb, 256)

        token = ScopeToken(
            scope_hash="hash123",
            allowed_domains=("*.example.com", "api.target.com"),
            allowed_cidrs=("10.0.0.0/8",),
            forbidden_paths=("/admin", "/logout"),
        )
        token_d = token.to_dict()
        self.assertIn("*.example.com", token_d["allowed_domains"])
        self.assertIn("/admin", token_d["forbidden_paths"])

    def test_execution_request_and_result_roundtrip(self):
        target = TargetSpec(host="api.target.com", port=443, scheme="https", path="/login")
        action = ActionSpec(action_id="act_01", action_type="probe", tool_or_detector="jwt_probe")
        limits = ResourceLimits(timeout_seconds=120.0)
        token = ScopeToken(scope_hash="abc", allowed_domains=("api.target.com",))

        req = ExecutionRequest(
            request_id="req_12345",
            tenant_id="tenant_alpha",
            target=target,
            stage="probing",
            actions=(action,),
            resource_limits=limits,
            scope_token=token,
            deadline=time.time() + 300,
        )

        self.assertIsInstance(req, ExecutionRequestProtocol)
        req_d = req.to_dict()
        self.assertEqual(req_d["request_id"], "req_12345")
        self.assertEqual(req_d["tenant_id"], "tenant_alpha")
        self.assertEqual(req_d["stage"], "probing")
        self.assertEqual(len(req_d["actions"]), 1)

        reconstructed_req = ExecutionRequest.from_dict(req_d)
        self.assertEqual(reconstructed_req.request_id, req.request_id)
        self.assertEqual(reconstructed_req.target.host, "api.target.com")
        self.assertEqual(reconstructed_req.actions[0].tool_or_detector, "jwt_probe")

        # Test ExecutionResult
        finding = Finding(
            category="auth",
            title="JWT Weak Key",
            url="https://api.target.com",
            severity="HIGH",
            confidence=0.95,
        )
        res = ExecutionResult(
            request_id="req_12345",
            tenant_id="tenant_alpha",
            outcome="COMPLETED",
            duration_seconds=1.234,
            findings=(finding,),
            artifacts=(("proof", {"token": "xyz"}),),
        )
        self.assertIsInstance(res, ExecutionResultProtocol)
        res_d = res.to_dict()
        self.assertEqual(res_d["outcome"], "COMPLETED")
        self.assertEqual(len(res_d["findings"]), 1)
        self.assertEqual(res_d["artifacts"]["proof"]["token"], "xyz")


class TestExecutionAuthorizer(unittest.TestCase):
    def test_authorize_valid_request(self):
        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
        authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)
        req = ExecutionRequest(
            request_id="req_valid",
            tenant_id="tenant_1",
            target=TargetSpec(host="sub.example.com", path="/api/items"),
            stage="probing",
            scope_token=ScopeToken(
                scope_hash="h1",
                allowed_domains=("*.example.com",),
                forbidden_paths=("/admin",),
            ),
            deadline=time.time() + 100,
        )
        ticket = authorizer.authorize(req)
        self.assertIsInstance(ticket, AuthorizedExecutionTicket)
        self.assertEqual(ticket.request_id, "req_valid")
        self.assertEqual(ticket.tenant_id, "tenant_1")
        self.assertNotEqual(ticket.signature, "")

    def test_reject_out_of_scope_domain(self):
        authorizer = ExecutionAuthorizer()
        req = ExecutionRequest(
            request_id="req_invalid_domain",
            tenant_id="tenant_1",
            target=TargetSpec(host="malicious.evil.com", path="/api"),
            stage="probing",
            scope_token=ScopeToken(
                scope_hash="h1",
                allowed_domains=("example.com",),
            ),
        )
        with self.assertRaises(ScopeAuthorizationError):
            authorizer.authorize(req)

    def test_reject_forbidden_path(self):
        authorizer = ExecutionAuthorizer()
        req = ExecutionRequest(
            request_id="req_forbidden",
            tenant_id="tenant_1",
            target=TargetSpec(host="example.com", path="/admin/delete"),
            stage="probing",
            scope_token=ScopeToken(
                scope_hash="h1",
                allowed_domains=("example.com",),
                forbidden_paths=("/admin",),
            ),
        )
        with self.assertRaises(ScopeAuthorizationError):
            authorizer.authorize(req)

    def test_reject_expired_deadline(self):
        authorizer = ExecutionAuthorizer()
        req = ExecutionRequest(
            request_id="req_expired",
            tenant_id="tenant_1",
            target=TargetSpec(host="example.com"),
            stage="probing",
            deadline=time.time() - 10,
        )
        with self.assertRaises(ScopeAuthorizationError):
            authorizer.authorize(req)


class TestStatelessExecutionWorker(unittest.TestCase):
    def test_end_to_end_worker_execution(self):
        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
        authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)
        worker = ExecutionRequestWorker(authorizer=authorizer)

        finding_dict = {
            "category": "sqli",
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "url": "https://example.com/api/users",
        }

        action = ActionSpec(
            action_id="act_sqli",
            action_type="probe",
            tool_or_detector="sqli_detector",
            payload=(("emits_finding", True), ("finding", finding_dict)),
        )

        req = ExecutionRequest(
            request_id="req_exec_001",
            tenant_id="tenant_test",
            target=TargetSpec(host="example.com", path="/api/users"),
            stage="probing",
            actions=(action,),
            scope_token=ScopeToken(scope_hash="h_test", allowed_domains=("example.com",)),
            deadline=time.time() + 60,
        )

        # 1. Authorize
        ticket = authorizer.authorize(req)

        # 2. Worker executes directly from ticket (Contract of Intent)
        res = worker.execute(ticket)

        self.assertEqual(res.outcome, "COMPLETED")
        self.assertEqual(res.request_id, "req_exec_001")
        self.assertEqual(res.tenant_id, "tenant_test")
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].title, "SQL Injection")
        self.assertEqual(res.findings[0].severity, "critical")
        self.assertGreater(len(res.artifacts), 0)
        self.assertGreaterEqual(res.duration_seconds, 0.0)

    def test_custom_handler_registration(self):
        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
        authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)
        worker = ExecutionRequestWorker(authorizer=authorizer)
        worker.register_handler(
            "custom_fuzz",
            lambda action, req: {"custom_key": "fuzz_payload_success", "host": req.target.host},
        )

        action = ActionSpec(
            action_id="act_fuzz",
            action_type="custom_fuzz",
            tool_or_detector="custom_fuzzer",
        )

        req = ExecutionRequest(
            request_id="req_fuzz",
            tenant_id="default",
            target=TargetSpec(host="fuzz.target.com"),
            stage="fuzzing",
            actions=(action,),
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("fuzz.target.com",)),
        )

        ticket = authorizer.authorize(req)
        res = worker.execute(ticket)
        self.assertEqual(res.outcome, "COMPLETED")
        artifacts = dict(res.artifacts)
        self.assertIn("action_act_fuzz", artifacts)
        self.assertEqual(artifacts["action_act_fuzz"]["custom_key"], "fuzz_payload_success")

    def test_reject_raw_unauthorized_execution_request(self):
        worker = ExecutionRequestWorker()
        raw_req = ExecutionRequest(
            request_id="raw_bypass_attempt",
            tenant_id="default",
            target=TargetSpec(host="bypass.example.com"),
            stage="probing",
        )
        # Attempting to execute raw request without ticket MUST be rejected
        res = worker.execute(raw_req)  # type: ignore[arg-type]
        self.assertEqual(res.outcome, "REJECTED")
        self.assertIn("Worker strictly requires an AuthorizedExecutionTicket", res.error)

    def test_identity_propagation_and_ticket_consumption(self):
        from src.decision.models import CandidateLease

        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
        authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)
        worker = ExecutionRequestWorker(authorizer=authorizer)

        lease = CandidateLease(
            candidate_id="cand_101",
            target_url="https://example.com/api/test",
            execution_id="exec_999",
            lease_id="lease_888",
            worker_id="worker_01",
            expires_at=time.time() + 60.0,
        )
        self.assertEqual(lease.candidate_id, "cand_101")
        self.assertEqual(lease.lease_id, "lease_888")

        req = ExecutionRequest(
            request_id="req_ident",
            tenant_id="tenant_x",
            target=TargetSpec(host="example.com", path="/api/test"),
            stage="probing",
            execution_id="exec_999",
            job_id="job_777",
            candidate_id="cand_101",
            lease_id="lease_888",
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("example.com",)),
        )

        ticket = authorizer.authorize(req)

        # 1. First execution consumes ticket successfully and preserves identity
        res = worker.execute(ticket)
        self.assertEqual(res.outcome, "COMPLETED")
        self.assertEqual(res.execution_id, "exec_999")
        self.assertEqual(res.job_id, "job_777")
        self.assertEqual(res.candidate_id, "cand_101")
        self.assertEqual(res.lease_id, "lease_888")

        # 2. Second execution with same ticket must be REJECTED (replay protection)
        replay_res = worker.execute(ticket)
        self.assertEqual(replay_res.outcome, "REJECTED")
        self.assertIn("failed consumption", replay_res.error)
