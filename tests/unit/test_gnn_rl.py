"""Unit tests for pure-NumPy GNN link prediction and Q-learning RL probe selection agent."""

from __future__ import annotations

from src.intelligence.ml.gnn_predict import GNNPredictor, ProbeSelectionRLAgent


def test_gnn_link_prediction() -> None:
    """Test GNNPredictor initialized with nodes/edges and predicts unseen pivots."""
    predictor = GNNPredictor(seed=42)

    # Build a simple threat graph with a finding and endpoints
    nodes = [
        {"id": "subdomain:api.example.com", "type": "subdomain", "severity": "info"},
        {"id": "url:https://api.example.com/v1/auth", "type": "endpoint", "severity": "info"},
        {"id": "finding:auth_bypass_01", "type": "finding", "severity": "high"},
        {"id": "subdomain:portal.example.com", "type": "subdomain", "severity": "info"},
    ]

    # Existing connections:
    # api.example.com serves the /v1/auth endpoint.
    # The finding auth_bypass_01 affects api.example.com.
    # portal.example.com is currently unconnected.
    edges = [
        {
            "source": "subdomain:api.example.com",
            "target": "url:https://api.example.com/v1/auth",
            "label": "serves",
        },
        {
            "source": "subdomain:api.example.com",
            "target": "finding:auth_bypass_01",
            "label": "has_vuln",
        },
    ]

    predicted = predictor.predict_links(nodes, edges, threshold=0.1)

    assert isinstance(predicted, list)
    # The GNN should produce predicted links for unseen pivots
    for edge in predicted:
        assert "source" in edge
        assert "target" in edge
        assert edge["label"] == "predicted_pivot"
        assert "confidence" in edge["metadata"]
        assert edge["metadata"]["predicted"] is True


def test_rl_probe_selection() -> None:
    """Test ProbeSelectionRLAgent states, Q-value initialization, and optimal ranking."""
    agent = ProbeSelectionRLAgent()

    # 1. API endpoint state should boost jwt/idor/fuzzing
    api_url = "https://api.example.com/v1/users/profile"
    api_sequence = agent.get_optimal_probe_sequence(api_url)
    assert api_sequence[0] == "fuzzing_campaign" or "jwt" in api_sequence[:3]

    # 2. Auth endpoint state should boost auth_bypass
    auth_url = "https://example.com/login"
    auth_sequence = agent.get_optimal_probe_sequence(auth_url)
    assert "auth_bypass" in auth_sequence[:2]

    # 3. Parameterized endpoint state should boost sqli
    param_url = "https://example.com/search?query=test"
    param_sequence = agent.get_optimal_probe_sequence(param_url)
    assert "sqli" in param_sequence[:2] or "fuzzing_campaign" in param_sequence[:2]

    # 4. Learning updates
    state = agent._get_state(api_url)
    agent.update(state, "jwt", 10.0, state)
    updated_sequence = agent.get_optimal_probe_sequence(api_url)
    # After high reward, jwt should be the top selection
    assert updated_sequence[0] == "jwt"
