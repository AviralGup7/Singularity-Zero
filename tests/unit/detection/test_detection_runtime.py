"""Tests for detection runtime module."""

from src.analysis.plugin_runtime import AnalysisExecutionContext
from src.analysis.plugin_runtime_models import DetectionGraphContext
from src.detection.runtime import prime_detection_context, run_detection_plugins


class TestPrimeDetectionContext:
    def test_returns_analysis_execution_context(self) -> None:
        ctx = prime_detection_context(urls={"https://example.com"}, responses=[])
        assert isinstance(ctx, AnalysisExecutionContext)

    def test_urls_are_set(self) -> None:
        urls = {"https://example.com", "https://api.example.com"}
        ctx = prime_detection_context(urls=urls, responses=[])
        assert ctx.urls == urls

    def test_responses_are_set(self) -> None:
        responses = [{"url": "https://example.com", "status_code": 200}]
        ctx = prime_detection_context(urls=set(), responses=responses)
        assert ctx.responses == responses

    def test_priority_urls_default_empty(self) -> None:
        ctx = prime_detection_context(urls=set(), responses=[])
        assert ctx.priority_urls == set()

    def test_priority_urls_are_set(self) -> None:
        priority = ["https://example.com/api"]
        ctx = prime_detection_context(urls=set(), responses=[], priority_urls=priority)
        assert ctx.priority_urls == set(priority)

    def test_response_cache_can_be_passed(self) -> None:
        class FakeCache:
            pass

        cache = FakeCache()
        ctx = prime_detection_context(urls=set(), responses=[], response_cache=cache)
        assert ctx.response_cache is cache

    def test_detection_graph_can_be_passed(self) -> None:
        graph_ctx = DetectionGraphContext(
            execution=None,
            endpoints={},
            identities={},
            flow_edges=[],
            mutation_results=[],
            evidence=[],
            artifacts={},
            results={},
        )
        ctx = prime_detection_context(urls=set(), responses=[], detection_graph=graph_ctx)
        assert graph_ctx.execution is ctx


class TestRunDetectionPlugins:
    def _make_context(self) -> AnalysisExecutionContext:
        return AnalysisExecutionContext(
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

    def test_returns_dict(self) -> None:
        result = run_detection_plugins(self._make_context())
        assert isinstance(result, dict)

    def test_result_keys_are_strings(self) -> None:
        result = run_detection_plugins(self._make_context())
        for key in result:
            assert isinstance(key, str)

    def test_result_values_are_lists(self) -> None:
        result = run_detection_plugins(self._make_context())
        for value in result.values():
            assert isinstance(value, list)

    def test_empty_context_returns_empty_lists(self) -> None:
        result = run_detection_plugins(self._make_context())
        for value in result.values():
            assert value == []


class TestDetectionDispatch:
    def _make_context(self) -> AnalysisExecutionContext:
        return AnalysisExecutionContext(
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

    def test_dispatch_to_correct_handlers(self) -> None:
        result = run_detection_plugins(self._make_context())
        from src.analysis.plugin_runtime import ANALYZER_BINDINGS

        for key in ANALYZER_BINDINGS:
            assert key in result

    def test_dispatch_handles_all_bindings(self) -> None:
        result = run_detection_plugins(self._make_context())
        from src.analysis.plugin_runtime import ANALYZER_BINDINGS

        assert set(result.keys()) == set(ANALYZER_BINDINGS.keys())


class TestDetectionRuntimeErrorHandling:
    def test_runtime_handles_empty_urls(self) -> None:
        ctx = prime_detection_context(urls=set(), responses=[])
        result = run_detection_plugins(ctx)
        assert isinstance(result, dict)

    def test_runtime_handles_empty_responses(self) -> None:
        ctx = prime_detection_context(urls={"https://example.com"}, responses=[])
        result = run_detection_plugins(ctx)
        assert isinstance(result, dict)

    def test_runtime_does_not_raise_on_large_url_set(self) -> None:
        urls = {f"https://example.com/path{i}" for i in range(100)}
        ctx = prime_detection_context(urls=urls, responses=[])
        result = run_detection_plugins(ctx)
        assert isinstance(result, dict)

    def test_runtime_handles_responses_with_missing_keys(self) -> None:
        responses = [
            {"url": "https://example.com"},
            {"url": "https://api.example.com", "status_code": 200},
        ]
        ctx = prime_detection_context(urls=set(), responses=responses)
        result = run_detection_plugins(ctx)
        assert isinstance(result, dict)

    def test_runtime_handles_responses_with_none_values(self) -> None:
        responses = [{"url": None, "status_code": None, "body": None}]
        ctx = prime_detection_context(urls=set(), responses=responses)
        result = run_detection_plugins(ctx)
        assert isinstance(result, dict)
