import time
import unittest
from http.cookiejar import CookieJar

from src.core.models import Request, Response
from src.core.session import Session
from src.execution.scenario_engine import (  # type: ignore[attr-defined]
    ScenarioExecutionEngine,
)
from src.execution.scenario_models import (
    ScenarioStep,
    StepAssertion,
    ValueExtractor,
)


class ScenarioEngineTests(unittest.TestCase):
    def test_ordered_steps_extract_and_reuse_values(self) -> None:
        observed_requests: list[Request] = []

        def fake_transport(request: Request, _: CookieJar) -> Response:
            observed_requests.append(request)
            if request.url.endswith("/login"):
                return Response(
                    requested_url=request.url,
                    final_url=request.url,
                    status_code=200,
                    headers={"X-Session": "abc-session"},
                    body='{"token":"tok-123","user":{"id":"42"}}',
                )
            if request.url.endswith("/users/42"):
                return Response(
                    requested_url=request.url,
                    final_url=request.url,
                    status_code=200,
                    headers={},
                    body="ok",
                )
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=404,
                headers={},
                body="missing",
                error="not_found",
            )

        engine = ScenarioExecutionEngine(
            default_headers={"X-Client": "scenario"},
            transport=fake_transport,
        )
        steps = [
            ScenarioStep(
                name="login",
                request=Request(method="POST", url="https://api.example.com/login", body="{}"),
                extractors=(
                    ValueExtractor(name="token", source="json", json_path="token"),
                    ValueExtractor(name="user_id", source="json", json_path="user.id"),
                ),
                assertions=(StepAssertion(expected_statuses=(200,), expect_success=True),),
            ),
            ScenarioStep(
                name="read-profile",
                request=Request(
                    method="GET",
                    url="https://api.example.com/users/{{ user_id }}",
                    headers={"Authorization": "Bearer {{token}}"},
                ),
                assertions=(StepAssertion(expected_statuses=(200,), body_contains=("ok",)),),
            ),
        ]

        result = engine.execute(steps, session_headers={"X-Trace": "trace-1"})

        self.assertTrue(result.success)
        self.assertEqual(len(result.steps), 2)
        self.assertEqual(result.variables.get("token"), "tok-123")
        self.assertEqual(result.variables.get("user_id"), "42")
        self.assertEqual(observed_requests[1].url, "https://api.example.com/users/42")
        self.assertEqual(observed_requests[1].headers.get("Authorization"), "Bearer tok-123")
        self.assertEqual(observed_requests[0].headers.get("X-Trace"), "trace-1")
        self.assertEqual(observed_requests[1].headers.get("X-Client"), "scenario")
        self.assertEqual(result.active_session, "default")

    def test_step_assertion_failure_stops_execution(self) -> None:
        call_count = 0

        def fake_transport(request: Request, _: CookieJar) -> Response:
            nonlocal call_count
            call_count += 1
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=500,
                headers={},
                body="boom",
                error="server_error",
            )

        engine = ScenarioExecutionEngine(transport=fake_transport)
        steps = [
            ScenarioStep(
                name="one",
                request=Request(method="GET", url="https://example.com/one"),
                assertions=(StepAssertion(expect_success=True),),
            ),
            ScenarioStep(
                name="two",
                request=Request(method="GET", url="https://example.com/two"),
            ),
        ]
        result = engine.execute(steps)
        self.assertFalse(result.success)
        self.assertEqual(call_count, 1)
        self.assertIn("expected success", result.steps[0].assertion_errors[0])

    def test_multi_user_sessions_attach_and_switch_dynamically(self) -> None:
        observed_requests: list[Request] = []

        def fake_transport(request: Request, _: CookieJar) -> Response:
            observed_requests.append(request)
            if request.url.endswith("/login"):
                return Response(
                    requested_url=request.url,
                    final_url=request.url,
                    status_code=200,
                    headers={"Set-Cookie": "sid=sid-a; Path=/"},
                    body='{"auth_token":"token-a"}',
                )
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=200,
                headers={},
                body="ok",
            )

        sessions = {
            "user_a": Session(headers={"X-Actor": "A"}, role="user", identity="alice"),
            "user_b": Session(
                headers={"X-Actor": "B"}, role="admin", identity="bob", auth_token="token-b"
            ),
        }
        engine = ScenarioExecutionEngine(transport=fake_transport)
        steps = [
            ScenarioStep(
                name="login-a",
                session_key="user_a",
                request=Request(method="POST", url="https://api.example.com/login", body="{}"),
                extractors=(
                    ValueExtractor(name="auth_token", source="json", json_path="auth_token"),
                ),
                assertions=(StepAssertion(expected_statuses=(200,), expect_success=True),),
            ),
            ScenarioStep(
                name="read-as-a",
                request=Request(method="GET", url="https://api.example.com/me"),
            ),
            ScenarioStep(
                name="read-as-b",
                session_key="user_b",
                request=Request(method="GET", url="https://api.example.com/admin"),
            ),
        ]

        result = engine.execute(steps, sessions=sessions, active_session="user_a")

        self.assertTrue(result.success)
        self.assertEqual(result.active_session, "user_b")
        self.assertEqual(observed_requests[0].headers.get("X-Actor"), "A")
        self.assertEqual(observed_requests[1].headers.get("Authorization"), "Bearer token-a")
        self.assertIn("sid=sid-a", observed_requests[1].headers.get("Cookie", ""))
        self.assertEqual(observed_requests[2].headers.get("X-Actor"), "B")
        self.assertEqual(observed_requests[2].headers.get("Authorization"), "Bearer token-b")

    def test_parallel_groups_barriers_branching_and_temporal_assertions(self) -> None:
        observed_requests: list[tuple[str, float]] = []

        def fake_transport(request: Request, _: CookieJar) -> Response:
            now = time.monotonic()
            observed_requests.append((request.url, now))
            if request.url.endswith("/prep"):
                return Response(
                    requested_url=request.url,
                    final_url=request.url,
                    status_code=200,
                    headers={},
                    body='{"token":"tok-parallel"}',
                    latency_seconds=0.01,
                )
            if request.url.endswith("/parallel-a") or request.url.endswith("/parallel-b"):
                time.sleep(0.05)
                return Response(
                    requested_url=request.url,
                    final_url=request.url,
                    status_code=200,
                    headers={},
                    body="ok",
                    latency_seconds=0.05,
                )
            if request.url.endswith("/final"):
                return Response(
                    requested_url=request.url,
                    final_url=request.url,
                    status_code=200,
                    headers={},
                    body="done",
                    latency_seconds=0.01,
                )
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=404,
                headers={},
                body="missing",
                error="not_found",
            )

        engine = ScenarioExecutionEngine(transport=fake_transport)
        steps = [
            ScenarioStep(
                name="prep",
                actor="buyer",
                request=Request(method="GET", url="https://api.example.com/prep"),
                extractors=(ValueExtractor(name="token", source="json", json_path="token"),),
                publish_barrier="ready",
                assertions=(StepAssertion(expect_success=True),),
            ),
            ScenarioStep(
                name="parallel-a",
                actor="buyer",
                parallel_group="race",
                wait_for_barriers=("ready",),
                when="token",
                request=Request(
                    method="GET",
                    url="https://api.example.com/parallel-a",
                    headers={"Authorization": "Bearer {{token}}"},
                ),
                assertions=(StepAssertion(expect_success=True, max_latency_seconds=0.2),),
            ),
            ScenarioStep(
                name="parallel-b",
                actor="reviewer",
                parallel_group="race",
                wait_for_barriers=("ready",),
                when="step:prep.passed",
                request=Request(method="GET", url="https://api.example.com/parallel-b"),
                assertions=(StepAssertion(expect_success=True, max_latency_seconds=0.2),),
            ),
            ScenarioStep(
                name="skipped-branch",
                when="missing_value",
                request=Request(method="GET", url="https://api.example.com/should-not-run"),
            ),
            ScenarioStep(
                name="final",
                wait_for_steps=("parallel-a", "parallel-b"),
                request=Request(method="GET", url="https://api.example.com/final"),
                assertions=(
                    StepAssertion(
                        expect_success=True,
                        after_step="parallel-a",
                        relative_to_step="parallel-b",
                        min_delay_seconds=0.0,
                        max_delay_seconds=0.5,
                    ),
                ),
            ),
        ]

        sessions = {
            "buyer": Session(headers={"X-Actor": "buyer"}, role="user", identity="alice"),
            "reviewer": Session(headers={"X-Actor": "reviewer"}, role="admin", identity="bob"),
        }

        result = engine.execute(steps, sessions=sessions, active_session="buyer")

        self.assertTrue(result.success)
        result_by_name = {item.name: item for item in result.steps}
        self.assertTrue(result_by_name["skipped-branch"].skipped)
        self.assertEqual(result_by_name["parallel-a"].actor, "buyer")
        self.assertEqual(result_by_name["parallel-b"].actor, "reviewer")
        self.assertEqual(result_by_name["parallel-a"].session_key, "buyer")
        self.assertEqual(result_by_name["parallel-b"].session_key, "reviewer")
        self.assertIn("tok-parallel", result.variables.get("token", ""))

        parallel_a = result_by_name["parallel-a"]
        parallel_b = result_by_name["parallel-b"]
        self.assertLess(abs(parallel_a.started_at - parallel_b.started_at), 0.08)
        self.assertGreaterEqual(
            result_by_name["final"].started_at,
            max(parallel_a.completed_at, parallel_b.completed_at),
        )

    def test_parallel_after_step_assertion_is_enforced_for_same_wave_steps(self) -> None:
        observed_requests: list[str] = []

        def fake_transport(request: Request, _: CookieJar) -> Response:
            observed_requests.append(request.url)
            if request.url.endswith("/first"):
                time.sleep(0.05)
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=200,
                headers={},
                body="ok",
                latency_seconds=0.01,
            )

        engine = ScenarioExecutionEngine(transport=fake_transport)
        steps = [
            ScenarioStep(
                name="first",
                parallel_group="race",
                request=Request(method="GET", url="https://api.example.com/first"),
                assertions=(StepAssertion(expect_success=True),),
            ),
            ScenarioStep(
                name="second",
                parallel_group="race",
                request=Request(method="GET", url="https://api.example.com/second"),
                assertions=(StepAssertion(expect_success=True, after_step="first"),),
            ),
        ]

        result = engine.execute(steps, stop_on_failure=False)

        self.assertEqual(len(observed_requests), 2)
        result_by_name = {item.name: item for item in result.steps}
        self.assertFalse(result_by_name["second"].passed)
        self.assertIn("start after 'first'", " ".join(result_by_name["second"].assertion_errors))

    def test_step_passed_condition_treats_skipped_step_as_not_passed(self) -> None:
        observed_requests: list[str] = []

        def fake_transport(request: Request, _: CookieJar) -> Response:
            observed_requests.append(request.url)
            return Response(
                requested_url=request.url,
                final_url=request.url,
                status_code=200,
                headers={},
                body="ok",
            )

        engine = ScenarioExecutionEngine(transport=fake_transport)
        steps = [
            ScenarioStep(
                name="gate",
                when="missing_flag",
                request=Request(method="GET", url="https://api.example.com/gate"),
            ),
            ScenarioStep(
                name="dependent",
                wait_for_steps=("gate",),
                when="step:gate.passed",
                request=Request(method="GET", url="https://api.example.com/dependent"),
            ),
        ]

        result = engine.execute(steps, stop_on_failure=False)

        self.assertEqual(observed_requests, [])
        result_by_name = {item.name: item for item in result.steps}
        self.assertTrue(result_by_name["gate"].skipped)
        self.assertTrue(result_by_name["dependent"].skipped)


if __name__ == "__main__":
    unittest.main()
