from src.learning.models.graph_node import GraphNodeType


class TestGraphNodeTypeEnum:
    """Tests for GraphNodeType enum."""

    def test_all_values(self):
        assert GraphNodeType.ENDPOINT.value == "endpoint"
        assert GraphNodeType.PARAMETER.value == "parameter"
        assert GraphNodeType.FINDING.value == "finding"
        assert GraphNodeType.TECH_STACK.value == "tech_stack"
        assert GraphNodeType.SESSION.value == "session"
        assert GraphNodeType.RESOURCE.value == "resource"
        assert GraphNodeType.HOST.value == "host"

    def test_from_value(self):
        assert GraphNodeType("endpoint") == GraphNodeType.ENDPOINT
        assert GraphNodeType("finding") == GraphNodeType.FINDING
