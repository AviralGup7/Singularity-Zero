"""Unit tests for src.analysis.plugin_runtime_models."""

import unittest

import pytest

from src.analysis.plugin_runtime_models import (
    AnalysisExecutionContext,
    AnalyzerBinding,
    DetectionGraphContext,
    EndpointEntity,
    EvidenceEntity,
    FlowEdge,
)


@pytest.mark.unit
class TestEndpointEntity(unittest.TestCase):
    def test_minimal_construction(self) -> None:
        e = EndpointEntity(endpoint_key="k", url="https://x.com/", host="x.com")
        self.assertEqual(e.endpoint_key, "k")
        self.assertEqual(e.url, "https://x.com/")
        self.assertEqual(e.host, "x.com")
        self.assertEqual(e.query_parameters, ())

    def test_frozen(self) -> None:
        e = EndpointEntity(endpoint_key="k", url="https://x.com/", host="x.com")
        with self.assertRaises(Exception):
            e.url = "https://other.com/"  # type: ignore[misc]

    def test_query_params_default(self) -> None:
        e = EndpointEntity(
            endpoint_key="k",
            url="https://x.com/",
            host="x.com",
            query_parameters=("a", "b"),
        )
        self.assertEqual(e.query_parameters, ("a", "b"))

    def test_equality(self) -> None:
        a = EndpointEntity(endpoint_key="k", url="u", host="h")
        b = EndpointEntity(endpoint_key="k", url="u", host="h")
        self.assertEqual(a, b)


@pytest.mark.unit
class TestFlowEdge(unittest.TestCase):
    def test_default_confidence(self) -> None:
        e = FlowEdge(source_key="a", target_key="b", edge_type="nav")
        self.assertEqual(e.confidence, 0.5)
        self.assertEqual(e.edge_type, "nav")

    def test_custom_confidence(self) -> None:
        e = FlowEdge(source_key="a", target_key="b", edge_type="x", confidence=0.9)
        self.assertEqual(e.confidence, 0.9)

    def test_frozen(self) -> None:
        e = FlowEdge(source_key="a", target_key="b", edge_type="x")
        with self.assertRaises(Exception):
            e.source_key = "z"  # type: ignore[misc]


@pytest.mark.unit
class TestEvidenceEntity(unittest.TestCase):
    def test_minimal_construction(self) -> None:
        e = EvidenceEntity(
            analyzer_key="xss", phase="discover", url="https://x/", summary="reflected"
        )
        self.assertEqual(e.analyzer_key, "xss")
        self.assertEqual(e.phase, "discover")
        self.assertEqual(e.url, "https://x/")
        self.assertEqual(e.summary, "reflected")
        self.assertEqual(e.severity, "info")
        self.assertIsNone(e.metadata)

    def test_custom_severity(self) -> None:
        e = EvidenceEntity(
            analyzer_key="sqli",
            phase="confirm",
            url="https://x/",
            summary="error-based",
            severity="critical",
            metadata={"db": "mysql"},
        )
        self.assertEqual(e.severity, "critical")
        self.assertEqual(e.metadata, {"db": "mysql"})

    def test_frozen(self) -> None:
        e = EvidenceEntity(analyzer_key="x", phase="p", url="u", summary="s")
        with self.assertRaises(Exception):
            e.url = "other"  # type: ignore[misc]


@pytest.mark.unit
class TestAnalyzerBinding(unittest.TestCase):
    def test_defaults(self) -> None:
        b = AnalyzerBinding(input_kind="url")
        self.assertIsNone(b.runner)
        self.assertIsNone(b.context_attr)
        self.assertIsNone(b.limit_key)
        self.assertIsNone(b.default_limit)
        self.assertEqual(b.phase, "discover")
        self.assertEqual(b.consumes, ())
        self.assertEqual(b.produces, ())
        self.assertIsNone(b.extra_kwargs)

    def test_custom_construction(self) -> None:
        b = AnalyzerBinding(
            input_kind="response",
            runner=lambda x: x,
            context_attr="responses",
            limit_key="max_responses",
            default_limit=100,
            phase="confirm",
            consumes=("url",),
            produces=("finding",),
            extra_kwargs={"debug": True},
        )
        self.assertEqual(b.phase, "confirm")
        self.assertEqual(b.default_limit, 100)
        self.assertEqual(b.consumes, ("url",))
        self.assertEqual(b.produces, ("finding",))
        self.assertEqual(b.extra_kwargs, {"debug": True})


@pytest.mark.unit
class TestAnalysisExecutionContext(unittest.TestCase):
    def test_default_construction(self) -> None:
        ctx = AnalysisExecutionContext(
            live_hosts=set(),
            urls=set(),
            priority_urls=set(),
            analysis_config={},
            header_targets=[],
            responses=[],
            response_map={},
            response_cache=None,
            ranked_items=[],
            flow_items=[],
            bulk_items=[],
            payload_items=[],
            token_findings=[],
            csrf_findings=[],
            ssti_findings=[],
            upload_findings=[],
            business_logic_findings=[],
            rate_limit_findings=[],
            jwt_findings=[],
            smuggling_findings=[],
            ssrf_findings=[],
            idor_findings=[],
        )
        self.assertEqual(ctx.live_hosts, set())
        self.assertEqual(ctx.urls, set())
        self.assertIsNone(ctx.response_cache)
        self.assertEqual(ctx.token_findings, [])

    def test_finding_lists_independent(self) -> None:
        ctx = AnalysisExecutionContext(
            live_hosts={"a.com"},
            urls={"https://a.com/"},
            priority_urls=set(),
            analysis_config={},
            header_targets=[],
            responses=[],
            response_map={},
            response_cache=None,
            ranked_items=[],
            flow_items=[],
            bulk_items=[],
            payload_items=[],
            token_findings=[],
            csrf_findings=[],
            ssti_findings=[],
            upload_findings=[],
            business_logic_findings=[],
            rate_limit_findings=[],
            jwt_findings=[],
            smuggling_findings=[],
            ssrf_findings=[],
            idor_findings=[],
        )
        ctx.token_findings.append({"k": "v"})
        self.assertEqual(len(ctx.token_findings), 1)
        self.assertEqual(len(ctx.csrf_findings), 0)


@pytest.mark.unit
class TestDetectionGraphContext(unittest.TestCase):
    def _build_ctx(self) -> DetectionGraphContext:
        exec_ctx = AnalysisExecutionContext(
            live_hosts=set(),
            urls=set(),
            priority_urls=set(),
            analysis_config={},
            header_targets=[],
            responses=[],
            response_map={},
            response_cache=None,
            ranked_items=[],
            flow_items=[],
            bulk_items=[],
            payload_items=[],
            token_findings=[],
            csrf_findings=[],
            ssti_findings=[],
            upload_findings=[],
            business_logic_findings=[],
            rate_limit_findings=[],
            jwt_findings=[],
            smuggling_findings=[],
            ssrf_findings=[],
            idor_findings=[],
        )
        return DetectionGraphContext(
            execution=exec_ctx,
            endpoints={},
            identities={},
            flow_edges=[],
            mutation_results=[],
            evidence=[],
            artifacts={},
            results={},
        )

    def test_has_artifacts_all_present(self) -> None:
        ctx = self._build_ctx()
        ctx.artifacts["foo"] = 1
        ctx.artifacts["bar"] = 2
        self.assertTrue(ctx.has_artifacts(("foo", "bar")))

    def test_has_artifacts_missing(self) -> None:
        ctx = self._build_ctx()
        ctx.artifacts["foo"] = 1
        self.assertFalse(ctx.has_artifacts(("foo", "bar")))

    def test_has_artifacts_empty_tuple(self) -> None:
        ctx = self._build_ctx()
        # all() of empty iterable is True
        self.assertTrue(ctx.has_artifacts(()))

    def test_put_artifact_adds(self) -> None:
        ctx = self._build_ctx()
        ctx.put_artifact("k", "v")
        self.assertEqual(ctx.artifacts["k"], "v")

    def test_put_artifact_overwrites(self) -> None:
        ctx = self._build_ctx()
        ctx.put_artifact("k", "v1")
        ctx.put_artifact("k", "v2")
        self.assertEqual(ctx.artifacts["k"], "v2")


if __name__ == "__main__":
    unittest.main()
