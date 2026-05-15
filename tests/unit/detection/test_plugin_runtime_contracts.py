import asyncio
import inspect
from urllib.parse import urlparse

from src.analysis.plugin_runtime import ANALYZER_BINDINGS
from src.analysis.plugin_runtime._runner import prime_analysis_primitives, run_registered_analyzer
from src.analysis.plugin_runtime_models import AnalyzerBinding

_INPUT_KIND_KWARGS: dict[str, tuple[str, ...]] = {
    "responses_only": ("responses",),
    "urls_only": ("urls",),
    "urls_and_responses": ("urls", "responses"),
    "priority_urls_and_cache": ("priority_urls", "response_cache"),
    "priority_urls_only": ("priority_urls",),
    "ranked_items_and_cache": ("ranked_items", "response_cache"),
    "behavior_analysis": ("behavior_results",),
    "responses_and_bulk_items": ("responses", "bulk_items"),
    "header_targets_and_cache": ("header_targets", "response_cache"),
}


def _required_keyword_params(fn: object) -> set[str]:
    signature = inspect.signature(fn)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return set()
    return {
        p.name
        for p in signature.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        and p.default is inspect._empty
    }


def test_registered_analyzers_match_runtime_dispatch_contract() -> None:
    for analyzer_key, binding in ANALYZER_BINDINGS.items():
        if binding.runner is None:
            continue

        provided = set(_INPUT_KIND_KWARGS.get(binding.input_kind, ()))
        if binding.context_attr:
            provided.add(binding.context_attr)
        if binding.extra_kwargs:
            provided.update(binding.extra_kwargs.keys())
        if binding.limit_key or binding.default_limit is not None:
            provided.add("limit")

        missing = sorted(_required_keyword_params(binding.runner) - provided)
        assert not missing, (
            f"{analyzer_key} binding contract is stale; missing runtime kwargs: {missing}"
        )


def test_run_registered_analyzer_filters_non_absolute_finding_urls() -> None:
    def bad_payload_runner(
        *, urls: set[str], responses: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        _ = (urls, responses)
        return [
            {"url": "/relative/path", "severity": "low"},
            {"url": "example.com/admin", "severity": "medium"},
            {"url": "https://ok.example.com/path", "severity": "high"},
        ]

    binding = AnalyzerBinding(input_kind="urls_and_responses", runner=bad_payload_runner)
    ctx = prime_analysis_primitives(
        urls={"https://seed.example.com/path"},
        responses=[{"url": "https://seed.example.com/path", "headers": {}}],
    )

    findings = run_registered_analyzer(binding, ctx, analyzer_key="unit_test_binding")
    urls = {item["url"] for item in findings}

    assert "https://ok.example.com/path" in urls
    assert "https://example.com/admin" in urls
    assert all(urlparse(url).scheme and urlparse(url).netloc for url in urls)


def test_prime_analysis_primitives_drops_malformed_urls_from_context() -> None:
    ctx = prime_analysis_primitives(
        urls={"https://good.example.com", "/relative/path", ""},
        priority_urls=["api.example.com/v1", "/still-relative"],
        live_hosts={"edge.example.com", "not a url", "/relative"},
        header_targets=["edge.example.com", "/asset"],
        responses=[
            {"url": "/bad", "headers": {}},
            {"url": "https://good.example.com/ok", "headers": {}},
        ],
    )

    assert "https://good.example.com" in ctx.urls
    assert all(urlparse(url).scheme and urlparse(url).netloc for url in ctx.urls)
    assert all(urlparse(url).scheme and urlparse(url).netloc for url in ctx.priority_urls)
    assert all(urlparse(url).scheme and urlparse(url).netloc for url in ctx.live_hosts)
    assert len(ctx.responses) == 1
    assert ctx.responses[0]["url"] == "https://good.example.com/ok"


def test_run_registered_analyzer_executes_async_runner_results() -> None:
    async def async_runner(
        *,
        urls: set[str],
        responses: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        _ = responses
        await asyncio.sleep(0)
        return [{"url": next(iter(urls)), "severity": "high"}]

    seed_url = "https://seed.example.com/path"
    binding = AnalyzerBinding(input_kind="urls_and_responses", runner=async_runner)
    ctx = prime_analysis_primitives(
        urls={seed_url},
        responses=[{"url": seed_url, "headers": {}}],
    )

    findings = run_registered_analyzer(binding, ctx, analyzer_key="async_runner_binding")

    assert findings == [{"url": seed_url, "severity": "high"}]
