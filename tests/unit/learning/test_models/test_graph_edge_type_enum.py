from src.learning.models.graph_node import GraphEdgeType


class TestGraphEdgeTypeEnum:
    """Tests for GraphEdgeType enum."""

    def test_all_values(self):
        assert GraphEdgeType.DEPENDS_ON.value == "depends_on"
        assert GraphEdgeType.CO_OCCURS.value == "co_occurs"
        assert GraphEdgeType.CHAINS_TO.value == "chains_to"
        assert GraphEdgeType.SHARES_PARAMETER.value == "shares_parameter"
        assert GraphEdgeType.ENABLES.value == "enables"
        assert GraphEdgeType.LEAKS_TO.value == "leaks_to"
        assert GraphEdgeType.REDIRECTS_TO.value == "redirects_to"
        assert GraphEdgeType.EXPLOITS_SAME_RESOURCE.value == "exploits_same_resource"
        assert GraphEdgeType.SHARES_AUTH_CONTEXT.value == "shares_auth_context"
        assert GraphEdgeType.SHARES_TECH_STACK.value == "shares_tech_stack"
        assert GraphEdgeType.SIMILAR_PATTERN.value == "similar_pattern"

    def test_from_value(self):
        assert GraphEdgeType("co_occurs") == GraphEdgeType.CO_OCCURS
        assert GraphEdgeType("depends_on") == GraphEdgeType.DEPENDS_ON
