import unittest

from src.infrastructure.observability.tracing import (
    OTLPExporter,
)


class TestOTLPExporter(unittest.TestCase):
    def test_init_unavailable(self) -> None:
        exporter = OTLPExporter(endpoint="http://localhost:4317")
        assert isinstance(exporter.is_available, bool)

    def test_get_stats(self) -> None:
        exporter = OTLPExporter()
        stats = exporter.get_stats()
        assert "available" in stats
        assert "export_count" in stats
