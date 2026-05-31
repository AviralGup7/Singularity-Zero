from pathlib import Path
from typing import Any
from urllib.parse import unquote

from src.analysis.active.injection.proxy_ssrf import proxy_ssrf_probe
from src.analysis.active.injection.ssrf import ssrf_active_probe
from src.analysis.checks.active.ssrf_oob_validator import ssrf_oob_validator
from src.analysis.passive.detectors.detector_app_ssrf import scan_responses as app_ssrf_scan
from src.analysis.plugin_runtime import ANALYZER_BINDINGS
from src.analysis.plugin_runtime._runner import prime_analysis_primitives, run_registered_analyzer
from src.core.plugins.loader import DynamicPluginCatalog
from src.core.plugins.sandbox import ProcessSandboxCallable


class FakeResponseCache:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def request(
        self,
        url: str,
        method: str = "GET",
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        self.requests.append({"url": url, "method": method, "body": body, "headers": headers or {}})
        if "169.254.169.254" in url or (body and "169.254.169.254" in body):
            return {
                "url": url,
                "status_code": 200,
                "body_text": "ami-id: ami-12345678\ninstance-id: i-1234567890",
            }
        return None


def test_ssrf_plugins_have_registered_runners() -> None:
    assert ANALYZER_BINDINGS["ssrf_active_probe"].runner is ssrf_active_probe
    assert ANALYZER_BINDINGS["proxy_ssrf_probe"].runner is proxy_ssrf_probe
    assert ANALYZER_BINDINGS["application_ssrf_vector_detector"].runner is app_ssrf_scan
    assert ANALYZER_BINDINGS["ssrf_oob_validator"].runner is ssrf_oob_validator


def test_ssrf_active_probe_runtime_accepts_string_priority_urls() -> None:
    cache = FakeResponseCache()
    ctx = prime_analysis_primitives(
        urls={"https://api.example.com/fetch?url=https://public.example/image.png"},
        responses=[],
        priority_urls=["https://api.example.com/fetch?url=https://public.example/image.png"],
        response_cache=cache,
        analysis_config={"ssrf_probe_limit": 3},
    )

    findings = run_registered_analyzer(
        ANALYZER_BINDINGS["ssrf_active_probe"],
        ctx,
        analyzer_key="ssrf_active_probe",
    )

    assert findings
    assert (
        unquote(findings[0]["url"])
        == "https://api.example.com/fetch?url=https://public.example/image.png"
    )
    assert "aws_metadata_leak" in findings[0]["issues"]


def test_proxy_ssrf_probe_runtime_accepts_string_priority_urls() -> None:
    cache = FakeResponseCache()
    ctx = prime_analysis_primitives(
        urls={"https://api.example.com/proxy?url=https://public.example/feed.xml"},
        responses=[],
        priority_urls=["https://api.example.com/proxy?url=https://public.example/feed.xml"],
        response_cache=cache,
        analysis_config={"proxy_ssrf_limit": 3},
    )

    findings = run_registered_analyzer(
        ANALYZER_BINDINGS["proxy_ssrf_probe"],
        ctx,
        analyzer_key="proxy_ssrf_probe",
    )

    assert findings
    assert (
        unquote(findings[0]["url"])
        == "https://api.example.com/proxy?url=https://public.example/feed.xml"
    )
    assert findings[0]["type"] == "proxy_ssrf"
    assert findings[0]["severity"] in {"critical", "high"}


def test_ssrf_dynamic_plugin_manifest_is_ast_valid_and_sandbox_json_compatible(
    tmp_path: Path,
) -> None:
    plugin_file = tmp_path / "ssrf_metadata_hint.py"
    plugin_file.write_text(
        """
from src.core.plugins.sdk import manifest

PLUGIN_MANIFEST = manifest(
    id="ssrf.metadata_hint",
    name="SSRF Metadata Hint",
    version="1.0.0",
    kind="validator",
    description="Flags metadata-service SSRF hints in a JSON-only sandbox.",
    group="active",
    entrypoint="run",
    sandbox="process",
    tags=["ssrf"],
    consumes=["url"],
    produces=["finding"],
    timeout_seconds=5,
)


def run(payload):
    target = payload.get("target", {})
    url = target.get("url", "")
    if "169.254.169.254" not in url:
        return []
    return [{"url": url, "category": "ssrf", "severity": "high"}]
""".strip(),
        encoding="utf-8",
    )

    catalog = DynamicPluginCatalog((tmp_path,))
    records = catalog.refresh()

    assert len(records) == 1
    assert records[0].manifest.group == "active"
    runner = ProcessSandboxCallable(records[0].manifest, records[0].path)
    assert runner({"target": {"url": "https://api.example.com/fetch?url=169.254.169.254"}}) == [
        {
            "url": "https://api.example.com/fetch?url=169.254.169.254",
            "category": "ssrf",
            "severity": "high",
        }
    ]
