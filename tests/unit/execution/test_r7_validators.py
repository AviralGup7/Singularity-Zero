"""Tests for the new R7 validators: CORS, JWT, cache_poison, GraphQL, race."""

import unittest

from src.execution.validators.config.scoring_config import ScoringConfig
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.cache_poison import evaluate_cache_poison
from src.execution.validators.validators.cors import evaluate_cors
from src.execution.validators.validators.graphql import (
    INTROSPECTION_QUERY,
    evaluate_graphql,
)
from src.execution.validators.validators.jwt import (
    build_alg_none_token,
    crack_jwt_secret,
    detect_alg_none,
    evaluate_jwt,
    parse_jwt,
    sign_jwt_hmac,
)
from src.execution.validators.validators.race import (
    evaluate_race_condition,
    run_race_probe,
)


class _StubScoring(ScoringConfig):
    def __init__(self, **overrides: object) -> None:
        super().__init__(**overrides)


class TestCorsValidator(unittest.TestCase):
    def test_reflected_origin(self) -> None:
        scoring = _StubScoring(base=0.45, cap=0.93)
        result = evaluate_cors(
            request_origin="https://evil.example",
            response_headers={
                "Access-Control-Allow-Origin": "https://evil.example",
                "Access-Control-Allow-Credentials": "true",
            },
            scoring=scoring,
            in_scope=True,
        )
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)
        self.assertIn("reflected_origin", result["signals"])

    def test_null_origin(self) -> None:
        scoring = _StubScoring(base=0.45, cap=0.93)
        result = evaluate_cors(
            request_origin="https://evil.example",
            response_headers={
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            },
            scoring=scoring,
            in_scope=True,
        )
        self.assertIn("null_origin_allowed", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_wildcard_with_credentials(self) -> None:
        scoring = _StubScoring(base=0.45, cap=0.93)
        result = evaluate_cors(
            request_origin="https://evil.example",
            response_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            scoring=scoring,
            in_scope=True,
        )
        self.assertIn("wildcard_with_credentials", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_out_of_scope_downgrades(self) -> None:
        scoring = _StubScoring(base=0.45, cap=0.93)
        result = evaluate_cors(
            request_origin="https://evil.example",
            response_headers={
                "Access-Control-Allow-Origin": "https://evil.example",
            },
            scoring=scoring,
            in_scope=False,
        )
        self.assertEqual(result["status"], ValidationStatus.HEURISTIC.value)


class TestJwtValidator(unittest.TestCase):
    def _token(self) -> str:
        return sign_jwt_hmac(
            sign_jwt_hmac("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.signature", "secret"),
            "secret",
        )

    def test_parse_jwt(self) -> None:
        token = sign_jwt_hmac("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.AAAA", "secret")
        parsed = parse_jwt(token)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["header"]["alg"], "HS256")

    def test_detect_alg_none(self) -> None:
        token = build_alg_none_token(
            sign_jwt_hmac("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.AAAA", "secret")
        )
        self.assertIsNotNone(token)
        self.assertTrue(detect_alg_none(token))

    def test_crack_known_secret(self) -> None:
        token = sign_jwt_hmac("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.AAAA", "supersecret")
        self.assertEqual(
            crack_jwt_secret(token, candidate_secrets=["nope", "supersecret"]), "supersecret"
        )

    def test_evaluate_jwt_offline_inconclusive(self) -> None:
        token = sign_jwt_hmac("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.AAAA", "nope")
        result = evaluate_jwt(token=token, scoring=_StubScoring(), in_scope=False)
        self.assertIn(result["status"], {"INCONCLUSIVE", "HEURISTIC"})

    def test_evaluate_jwt_alg_none_accepted(self) -> None:
        token = sign_jwt_hmac("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.AAAA", "secret")
        result = evaluate_jwt(
            token=token,
            scoring=_StubScoring(),
            jwt_evaluate=lambda t: {"status_code": 200, "body": "ok"},
            in_scope=True,
        )
        self.assertIn("alg_none_accepted", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)


class TestCachePoisonValidator(unittest.TestCase):
    def test_cached_unkeyed_input(self) -> None:
        scoring = _StubScoring(base=0.45, cap=0.92)
        token = "cacheprobe-abcdef0123456789"
        result = evaluate_cache_poison(
            target_url="https://example.com",
            unkeyed_header="X-Forwarded-Host",
            probe_response={
                "status_code": 200,
                "headers": {"x-cache": "miss"},
                "body": f"Welcome, {token}",
                "probe_token": token,
            },
            followup_response={
                "status_code": 200,
                "headers": {"x-cache": "hit"},
                "body": f"Welcome, {token}",
            },
            scoring=scoring,
            in_scope=True,
        )
        self.assertIn("cached_unkeyed_input", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_no_token_returns_inconclusive(self) -> None:
        scoring = _StubScoring()
        result = evaluate_cache_poison(
            target_url="https://example.com",
            unkeyed_header="X-Forwarded-Host",
            probe_response={"status_code": 200, "headers": {}, "body": ""},
            followup_response={"status_code": 200, "headers": {}, "body": ""},
            scoring=scoring,
            in_scope=True,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)


class TestGraphqlValidator(unittest.TestCase):
    def test_introspection_exposed(self) -> None:
        scoring = _StubScoring()
        result = evaluate_graphql(
            endpoint="https://example.com/graphql",
            scoring=scoring,
            graphql_request=lambda _ep, _q: {
                "status_code": 200,
                "body": '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
            },
            in_scope=True,
        )
        self.assertIn("introspection_exposed", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_no_callable_returns_inconclusive(self) -> None:
        scoring = _StubScoring()
        result = evaluate_graphql(
            endpoint="https://example.com/graphql",
            scoring=scoring,
            graphql_request=None,
            in_scope=True,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)

    def test_batch_amplification(self) -> None:
        scoring = _StubScoring()
        result = evaluate_graphql(
            endpoint="https://example.com/graphql",
            scoring=scoring,
            graphql_request=lambda _ep, q: {
                "status_code": 200,
                "body": '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]',
            },
            in_scope=True,
        )
        self.assertIn("batch_amplification", result["signals"])


class TestRaceValidator(unittest.TestCase):
    def test_duplicate_success(self) -> None:
        scoring = _StubScoring()
        result = evaluate_race_condition(
            target_url="https://example.com/redeem",
            responses=[
                {"status_code": 200, "body": "ok"},
                {"status_code": 200, "body": "ok"},
                {"status_code": 200, "body": "ok"},
            ],
            scoring=scoring,
            expected_concurrency=3,
            in_scope=True,
        )
        self.assertIn("duplicate_success", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_inconsistent_responses(self) -> None:
        scoring = _StubScoring()
        result = evaluate_race_condition(
            target_url="https://example.com/redeem",
            responses=[
                {"status_code": 200, "body": "ok"},
                {"status_code": 500, "body": "error"},
            ],
            scoring=scoring,
            expected_concurrency=2,
            in_scope=True,
        )
        self.assertIn("inconsistent_response", result["signals"])

    def test_run_race_probe_returns_responses(self) -> None:
        counter = {"n": 0}

        def runner() -> dict[str, object]:
            counter["n"] += 1
            return {"status_code": 200, "body": "ok"}

        responses = run_race_probe(runner=runner, concurrency=3)
        self.assertEqual(len(responses), 3)
        self.assertEqual(counter["n"], 3)


class TestIntrospectionQueryConstant(unittest.TestCase):
    def test_introspection_query_contains_marker(self) -> None:
        self.assertIn("__schema", INTROSPECTION_QUERY)


if __name__ == "__main__":
    unittest.main()
