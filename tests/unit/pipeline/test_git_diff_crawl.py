"""Tests for the git_diff_crawl stage (incremental CI mode)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.contracts.pipeline_runtime import StageOutcome
from src.pipeline.services.pipeline_orchestrator.stages.git_diff_crawl import (
    _filter_url_set,
    _find_prior_recon_dir,
    _path_for_url,
    _read_priority_scores,
    _url_matches_changed_path,
    run_git_diff_crawl,
)


def _make_git_repo(tmp_path: Path) -> Path:
    """Create a real git repo with one initial commit for ``git diff`` to work."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("hello", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S603,S607
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "config", "user.email", "ci@example.com"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "config", "user.name", "CI"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "add", "."],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "commit", "-q", "-m", "init"],  # noqa: S607
        check=True,
    )
    return repo


class TestUrlHelpers:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://example.com/api/users", "/api/users"),
            ("https://example.com/", "/"),
            ("https://example.com", "/"),
            ("https://example.com/path?q=1", "/path"),
            ("not-a-url", None),
        ],
    )
    def test_path_for_url(self, url: str, expected: str | None) -> None:
        assert _path_for_url(url) == expected

    def test_url_matches_changed_path_substring(self) -> None:
        assert _url_matches_changed_path(
            "https://example.com/api/users", ["api/users.py"]
        )
        assert not _url_matches_changed_path(
            "https://example.com/api/users", ["src/api/posts.py"]
        )

    def test_filter_url_set(self) -> None:
        urls = {
            "https://example.com/api/users",
            "https://example.com/static/img.png",
            "https://example.com/other",
        }
        result = _filter_url_set(urls, ["api/users.py"])
        assert "https://example.com/api/users" in result
        assert "https://example.com/other" not in result


class TestPriorReconLookup:
    def test_find_prior_recon_dir_no_prior(self, tmp_path: Path) -> None:
        target_root = tmp_path / "target"
        run_dir = target_root / "run-1"
        run_dir.mkdir(parents=True)
        assert _find_prior_recon_dir(run_dir) is None

    def test_find_prior_recon_dir_picks_latest(self, tmp_path: Path) -> None:
        target_root = tmp_path / "target"
        run_a = target_root / "run-a"
        run_b = target_root / "run-b"
        run_a.mkdir(parents=True)
        run_b.mkdir(parents=True)
        (run_a / "priority_scores.json").write_text("[]", encoding="utf-8")
        (run_b / "priority_scores.json").write_text("[]", encoding="utf-8")
        import os
        import time

        # Force run-b to be newer
        t = time.time()
        os.utime(run_a / "priority_scores.json", (t - 10, t - 10))
        os.utime(run_b / "priority_scores.json", (t, t))
        current = target_root / "run-current"
        current.mkdir()
        assert _find_prior_recon_dir(current) == run_b

    def test_read_priority_scores_invalid(self, tmp_path: Path) -> None:
        p = tmp_path / "priority_scores.json"
        p.write_text("not json", encoding="utf-8")
        assert _read_priority_scores(tmp_path) == []

    def test_read_priority_scores_filters_non_mappings(self, tmp_path: Path) -> None:
        p = tmp_path / "priority_scores.json"
        p.write_text(json.dumps([{"url": "u1"}, "string", 42, {"url": "u2"}]), encoding="utf-8")
        items = _read_priority_scores(tmp_path)
        assert len(items) == 2


class TestRunGitDiffCrawl:
    @pytest.mark.asyncio
    async def test_skips_when_incremental_disabled(self, tmp_path: Path) -> None:
        ctx = SimpleNamespace(output_store=SimpleNamespace(run_dir=tmp_path))
        out = await run_git_diff_crawl(
            SimpleNamespace(incremental=False, base_ref=None),
            config=SimpleNamespace(),
            ctx=ctx,
        )
        assert out.outcome == StageOutcome.SKIPPED
        assert out.metrics["reason"] == "incremental_disabled"

    @pytest.mark.asyncio
    async def test_skips_when_no_base_ref(self, tmp_path: Path) -> None:
        ctx = SimpleNamespace(output_store=SimpleNamespace(run_dir=tmp_path))
        out = await run_git_diff_crawl(
            SimpleNamespace(incremental=True, base_ref=None),
            config=SimpleNamespace(),
            ctx=ctx,
        )
        assert out.outcome == StageOutcome.SKIPPED

    @pytest.mark.asyncio
    async def test_skips_when_no_prior_recon(self, tmp_path: Path) -> None:
        repo = _make_git_repo(tmp_path)
        target_root = repo / "target"
        run_dir = target_root / "run-1"
        run_dir.mkdir(parents=True)
        ctx = SimpleNamespace(output_store=SimpleNamespace(run_dir=run_dir))
        out = await run_git_diff_crawl(
            SimpleNamespace(
                incremental=True, base_ref="HEAD", repo_root=str(repo)
            ),
            config=SimpleNamespace(),
            ctx=ctx,
        )
        assert out.outcome == StageOutcome.SKIPPED
        assert out.metrics["reason"] == "no_prior_recon"

    @pytest.mark.asyncio
    async def test_filters_urls_by_changed_files(self, tmp_path: Path) -> None:
        repo = _make_git_repo(tmp_path)
        # Add a second commit that changes one file
        (repo / "api").mkdir()
        (repo / "api" / "users.py").write_text("def users(): pass", encoding="utf-8")
        subprocess.run(  # noqa: S603
            ["git", "-C", str(repo), "add", "."], check=True  # noqa: S607
        )
        subprocess.run(  # noqa: S603
            ["git", "-C", str(repo), "commit", "-q", "-m", "users"], check=True  # noqa: S607
        )
        # Create prior run data
        target_root = repo / "target"
        run_a = target_root / "run-a"
        run_b = target_root / "run-b"
        run_a.mkdir(parents=True)
        run_b.mkdir(parents=True)
        scores = [
            {"url": "https://example.com/api/users", "score": 50},
            {"url": "https://example.com/api/posts", "score": 50},
        ]
        (run_a / "priority_scores.json").write_text(json.dumps(scores), encoding="utf-8")
        (run_b / "priority_scores.json").write_text(json.dumps(scores), encoding="utf-8")
        # Make run-b newer than run-a
        import os
        import time

        t = time.time()
        os.utime(run_b / "priority_scores.json", (t, t))
        os.utime(run_a / "priority_scores.json", (t - 100, t - 100))

        run_dir = target_root / "run-current"
        run_dir.mkdir()
        ctx = SimpleNamespace(
            output_store=SimpleNamespace(run_dir=run_dir),
            urls={"https://example.com/initial"},
            result=SimpleNamespace(
                urls={"https://example.com/initial"},
                priority_urls=["https://example.com/api/users"],
                ranked_priority_urls=[{"url": "https://example.com/api/users"}],
            ),
        )
        out = await run_git_diff_crawl(
            SimpleNamespace(
                incremental=True, base_ref="HEAD~1", repo_root=str(repo)
            ),
            config=SimpleNamespace(),
            ctx=ctx,
        )
        assert out.outcome == StageOutcome.COMPLETED
        assert out.metrics["changed_files"] >= 1
        assert "https://example.com/api/users" in out.state_delta["urls"]

    @pytest.mark.asyncio
    async def test_git_diff_failure_marks_failed(self, tmp_path: Path) -> None:
        # No git repo: git diff should fail gracefully
        non_repo = tmp_path / "no-repo"
        non_repo.mkdir()
        target_root = non_repo / "target"
        run_dir = target_root / "run-1"
        run_dir.mkdir(parents=True)
        # Provide a stale prior run so we don't skip on "no_prior_recon"
        (run_dir / "priority_scores.json").write_text("[]", encoding="utf-8")

        ctx = SimpleNamespace(output_store=SimpleNamespace(run_dir=run_dir))
        out = await run_git_diff_crawl(
            SimpleNamespace(
                incremental=True, base_ref="HEAD", repo_root=str(non_repo)
            ),
            config=SimpleNamespace(),
            ctx=ctx,
        )
        assert out.outcome == StageOutcome.FAILED
        assert "error" in out.metrics or out.error
