from src.analysis.intelligence.endpoint_attack_graph import (
    AttackGraphEdge,
    AttackGraphNode,
    _identity_rank,
    _propagate_attack_confidence,
    _search_attack_chains,
    build_attack_graph,
)
from src.analysis.intelligence.endpoint_graphs import (
    build_auth_context_mapping,
    build_endpoint_relationship_graph,
    build_shared_parameter_tracking,
)
from src.analysis.intelligence.endpoint_graphs import (
    build_finding_graph as build_fg,
)



class TestAttackGraphHelpers:
    def test_identity_rank_public(self) -> None:
        assert _identity_rank("public") == 0

    def test_identity_rank_authenticated(self) -> None:
        assert _identity_rank("authenticated") == 1

    def test_identity_rank_privileged(self) -> None:
        assert _identity_rank("privileged") == 2

    def test_identity_rank_admin(self) -> None:
        assert _identity_rank("admin") == 2

    def test_identity_rank_unknown(self) -> None:
        assert _identity_rank("unknown") == 1

    def test_propagate_confidence_returns_dict(self) -> None:
        nodes = {
            "a": AttackGraphNode(
                "a", "/api", "https://example.com/api", "public", "api", "example.com", 0.5
            ),
        }
        edges: dict[tuple[str, str, str], AttackGraphEdge] = {}
        result = _propagate_attack_confidence(nodes, edges)
        assert isinstance(result, dict)
        assert "a" in result

    def test_search_chains_returns_list(self) -> None:
        nodes: dict[str, AttackGraphNode] = {}
        edges: dict[tuple[str, str, str], AttackGraphEdge] = {}
        propagated: dict[str, float] = {}
        result = _search_attack_chains(nodes, edges, propagated, limit=5, max_depth=3)
        assert isinstance(result, list)