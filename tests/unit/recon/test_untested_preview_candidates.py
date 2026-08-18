"""Coverage for previously untested preview-deployment hostname generators."""

from __future__ import annotations

import pytest

from src.recon.preview_deployments import (
    _extract_title,
    _guess_project_name_from_inputs,
    all_candidates_for_project,
    amplify_preview_candidates,
    azure_static_apps_candidates,
    firebase_preview_candidates,
    fly_io_pr_candidates,
    netlify_preview_candidates,
    parse_host_from_url,
    railway_pr_candidates,
    render_pr_candidates,
    vercel_preview_candidates,
)


@pytest.mark.unit
def test_vercel_preview_candidates() -> None:
    hosts = vercel_preview_candidates("Shop", branches=["Main", ""], users=["Acme"])
    assert "shop-git-main.vercel.app" in hosts
    assert "shop--git-main.vercel.app" in hosts
    assert "shop-git-main-acme.vercel.app" in hosts
    assert vercel_preview_candidates("  ") == set()


@pytest.mark.unit
def test_netlify_preview_candidates_normalize_branch_slashes() -> None:
    hosts = netlify_preview_candidates("app", branches=["feat/login"], hashes=["abc123"])
    assert "feat-login--app.netlify.app" in hosts
    assert "abc123--app.netlify.app" in hosts
    assert netlify_preview_candidates("") == set()


@pytest.mark.unit
def test_railway_and_render_skip_invalid_pr_numbers() -> None:
    assert railway_pr_candidates("svc", [12, "nope"]) == {"svc-pr-12.up.railway.app"}
    assert render_pr_candidates("svc", [3]) == {"svc-pr-3.onrender.com"}
    assert railway_pr_candidates("", [1]) == set()
    assert render_pr_candidates("svc", []) == set()


@pytest.mark.unit
def test_fly_io_emits_one_host_per_region() -> None:
    hosts = fly_io_pr_candidates("demo", [7])
    assert "demo-pr-7.iad.fly.dev" in hosts
    assert "demo-pr-7.syd.fly.dev" in hosts
    assert len(hosts) >= 6
    assert fly_io_pr_candidates("demo", ["x"]) == set()


@pytest.mark.unit
def test_amplify_firebase_azure_candidates() -> None:
    assert amplify_preview_candidates("shop", ["feat/x"]) == {"feat-x.shop.amplifyapp.com"}
    assert firebase_preview_candidates("my.app", ["live"]) == {"live.my-app.web.app"}
    assert azure_static_apps_candidates("my_app", ["feat/x"]) == {
        "my-app-feat-x.azurestaticapps.net"
    }
    assert amplify_preview_candidates("", ["main"]) == set()


@pytest.mark.unit
def test_all_candidates_for_project_unions_providers() -> None:
    hosts = all_candidates_for_project(
        "demo",
        branches=["main"],
        users=["ops"],
        netlify_hashes=["deadbeef"],
        pr_numbers=[1],
    )
    assert "demo-git-main.vercel.app" in hosts
    assert "main--demo.netlify.app" in hosts
    assert "deadbeef--demo.netlify.app" in hosts
    assert "demo-pr-1.up.railway.app" in hosts
    assert "demo-pr-1.onrender.com" in hosts
    assert "main.demo.amplifyapp.com" in hosts
    assert "main.demo.web.app" in hosts
    assert "demo-main.azurestaticapps.net" in hosts


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("", ""),
        ("https://Preview.Example.COM/path", "preview.example.com"),
        ("preview.example.com", "preview.example.com"),
    ],
)
def test_parse_host_from_url(url: str, expected: str) -> None:
    assert parse_host_from_url(url) == expected


@pytest.mark.unit
def test_extract_title_and_guess_project_name() -> None:
    assert _extract_title("") == ""
    assert _extract_title("<html><title>  Hello </title></html>") == "Hello"
    assert _extract_title("<div>no title</div>") == ""
    assert _guess_project_name_from_inputs(repo_slug="Acme/My_App") == "my-app"
    assert (
        _guess_project_name_from_inputs(git_remote="https://github.com/acme/shop.git") == "shop"
    )
    assert _guess_project_name_from_inputs(git_remote="git@github.com:acme/shop.git") == "shop"
    assert _guess_project_name_from_inputs() == ""
