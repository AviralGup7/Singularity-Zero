from dataclasses import FrozenInstanceError

import pytest

from src.api_tests.apitester.models import (
    ApiTestContext,
    ComparisonSummary,
    RequestSummary,
)


@pytest.mark.unit
class TestApiTestContext:
    def test_all_fields_populated(self) -> None:
        ctx = ApiTestContext(
            title="Test Title",
            severity="HIGH",
            confidence="MEDIUM",
            method="GET",
            url="https://api.example.com/users/456",
            baseline_url="https://api.example.com/users/123",
            path="/users/456",
            query="",
            baseline_path="/users/123",
            baseline_query="",
            parameter="user_id",
            variant="456",
            replay_id="replay-001",
            combined_signal="signal-a, signal-b",
            next_step="Compare responses",
        )
        assert ctx.title == "Test Title"
        assert ctx.severity == "HIGH"
        assert ctx.confidence == "MEDIUM"
        assert ctx.method == "GET"
        assert ctx.url == "https://api.example.com/users/456"
        assert ctx.baseline_url == "https://api.example.com/users/123"
        assert ctx.path == "/users/456"
        assert ctx.parameter == "user_id"
        assert ctx.variant == "456"
        assert ctx.replay_id == "replay-001"
        assert ctx.combined_signal == "signal-a, signal-b"
        assert ctx.next_step == "Compare responses"

    def test_frozen_dataclass_is_immutable(self) -> None:
        ctx = ApiTestContext(
            title="Immutable",
            severity="INFO",
            confidence="",
            method="POST",
            url="https://api.example.com/test",
            baseline_url="https://api.example.com/base",
            path="/test",
            query="",
            baseline_path="/base",
            baseline_query="",
            parameter="",
            variant="",
            replay_id="",
            combined_signal="",
            next_step="",
        )
        with pytest.raises((TypeError, AttributeError, FrozenInstanceError)):
            ctx.title = "changed"

    def test_empty_string_fields(self) -> None:
        ctx = ApiTestContext(
            title="",
            severity="",
            confidence="",
            method="",
            url="",
            baseline_url="",
            path="",
            query="",
            baseline_path="",
            baseline_query="",
            parameter="",
            variant="",
            replay_id="",
            combined_signal="",
            next_step="",
        )
        assert ctx.title == ""
        assert ctx.severity == ""
        assert ctx.method == ""

    def test_equality_same_values(self) -> None:
        kwargs = {
            "title": "Equal",
            "severity": "LOW",
            "confidence": "HIGH",
            "method": "DELETE",
            "url": "https://api.example.com/del",
            "baseline_url": "https://api.example.com/base",
            "path": "/del",
            "query": "id=1",
            "baseline_path": "/base",
            "baseline_query": "",
            "parameter": "id",
            "variant": "1",
            "replay_id": "r-1",
            "combined_signal": "none",
            "next_step": "done",
        }
        ctx1 = ApiTestContext(**kwargs)
        ctx2 = ApiTestContext(**kwargs)
        assert ctx1 == ctx2

    def test_inequality_different_values(self) -> None:
        ctx1 = ApiTestContext(
            title="A",
            severity="HIGH",
            confidence="MEDIUM",
            method="GET",
            url="https://a.com",
            baseline_url="https://b.com",
            path="/a",
            query="",
            baseline_path="/b",
            baseline_query="",
            parameter="p",
            variant="v",
            replay_id="r",
            combined_signal="s",
            next_step="n",
        )
        ctx2 = ApiTestContext(
            title="B",
            severity="HIGH",
            confidence="MEDIUM",
            method="GET",
            url="https://a.com",
            baseline_url="https://b.com",
            path="/a",
            query="",
            baseline_path="/b",
            baseline_query="",
            parameter="p",
            variant="v",
            replay_id="r",
            combined_signal="s",
            next_step="n",
        )
        assert ctx1 != ctx2

    def test_repr_contains_title(self) -> None:
        ctx = ApiTestContext(
            title="ReprTest",
            severity="INFO",
            confidence="",
            method="GET",
            url="https://x.com",
            baseline_url="https://y.com",
            path="/x",
            query="",
            baseline_path="/y",
            baseline_query="",
            parameter="",
            variant="",
            replay_id="",
            combined_signal="",
            next_step="",
        )
        assert "ReprTest" in repr(ctx)


@pytest.mark.unit
class TestRequestSummary:
    def test_successful_response(self) -> None:
        summary = RequestSummary(
            ok=True,
            error="",
            status_code=200,
            content_type="application/json",
            body_length=1024,
        )
        assert summary.ok is True
        assert summary.error == ""
        assert summary.status_code == 200
        assert summary.content_type == "application/json"
        assert summary.body_length == 1024

    def test_failed_response(self) -> None:
        summary = RequestSummary(
            ok=False,
            error="connection refused",
            status_code=None,
            content_type="",
            body_length=0,
        )
        assert summary.ok is False
        assert summary.error == "connection refused"
        assert summary.status_code is None
        assert summary.content_type == ""
        assert summary.body_length == 0

    def test_error_response_with_status(self) -> None:
        summary = RequestSummary(
            ok=True,
            error="",
            status_code=500,
            content_type="text/html",
            body_length=512,
        )
        assert summary.ok is True
        assert summary.status_code == 500

    def test_frozen_immutability(self) -> None:
        summary = RequestSummary(
            ok=True,
            error="",
            status_code=200,
            content_type="application/json",
            body_length=100,
        )
        with pytest.raises((TypeError, AttributeError, FrozenInstanceError)):
            summary.status_code = 404

    def test_equality(self) -> None:
        s1 = RequestSummary(
            ok=True,
            error="",
            status_code=200,
            content_type="application/json",
            body_length=100,
        )
        s2 = RequestSummary(
            ok=True,
            error="",
            status_code=200,
            content_type="application/json",
            body_length=100,
        )
        assert s1 == s2

    def test_inequality(self) -> None:
        s1 = RequestSummary(
            ok=True,
            error="",
            status_code=200,
            content_type="application/json",
            body_length=100,
        )
        s2 = RequestSummary(
            ok=True,
            error="",
            status_code=404,
            content_type="application/json",
            body_length=100,
        )
        assert s1 != s2


@pytest.mark.unit
class TestComparisonSummary:
    def test_no_differences(self) -> None:
        summary = ComparisonSummary(
            status_changed=False,
            length_changed=False,
            interesting_difference=False,
        )
        assert summary.status_changed is False
        assert summary.length_changed is False
        assert summary.interesting_difference is False

    def test_status_changed(self) -> None:
        summary = ComparisonSummary(
            status_changed=True,
            length_changed=False,
            interesting_difference=True,
        )
        assert summary.status_changed is True
        assert summary.interesting_difference is True

    def test_length_changed(self) -> None:
        summary = ComparisonSummary(
            status_changed=False,
            length_changed=True,
            interesting_difference=True,
        )
        assert summary.length_changed is True
        assert summary.status_changed is False

    def test_all_changed(self) -> None:
        summary = ComparisonSummary(
            status_changed=True,
            length_changed=True,
            interesting_difference=True,
        )
        assert summary.status_changed is True
        assert summary.length_changed is True
        assert summary.interesting_difference is True

    def test_frozen_immutability(self) -> None:
        summary = ComparisonSummary(
            status_changed=False,
            length_changed=False,
            interesting_difference=False,
        )
        with pytest.raises((TypeError, AttributeError, FrozenInstanceError)):
            summary.status_changed = True

    def test_equality(self) -> None:
        s1 = ComparisonSummary(
            status_changed=True, length_changed=True, interesting_difference=True
        )
        s2 = ComparisonSummary(
            status_changed=True, length_changed=True, interesting_difference=True
        )
        assert s1 == s2

    def test_repr(self) -> None:
        summary = ComparisonSummary(
            status_changed=True,
            length_changed=False,
            interesting_difference=True,
        )
        assert "ComparisonSummary" in repr(summary)
