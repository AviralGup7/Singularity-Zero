"""Tests for Grammar-Guided AST-Driven HTTP Fuzzer Campaign."""

from src.core.mutation_engine import generate_payloads_for_parameter
from src.fuzzing.ast_mutator import JSONASTMutator
from src.fuzzing.orchestrator import FuzzingOrchestrator


def test_json_ast_mutator_basic():
    mutator = JSONASTMutator()
    base_json = '{"user": "admin", "id": 123}'

    mutations = mutator.mutate(base_json)
    assert len(mutations) > 0
    for m in mutations:
        import json

        # Verify it's still valid JSON
        json.loads(m)


def test_mutation_engine_json_ast_integration():
    param_name = "data"
    param_value = '{"active": true}'

    payloads = generate_payloads_for_parameter(param_name, param_value)

    # Check if any payload came from the AST mutator
    assert any(p["reason"] == "json_ast_mutation" for p in payloads)


def test_orchestrator_generate_campaign_payloads_json():
    orch = FuzzingOrchestrator(target_endpoints=["/api"])
    payloads = orch.generate_campaign_payloads(
        endpoint="/api", param_name="input", base_value='{"cmd": "run"}', param_type="json"
    )

    assert any(p["strategy"] == "ast_grammar_guided" for p in payloads)
