"""Regression: IDOR mutations must keep valid path segments."""

from __future__ import annotations

import pytest

from src.analysis.intelligence.idor_mutations import (
    bulk_mutations,
    extract_path_identifier,
    generate_all_mutations,
    learn_id_pattern,
    mutate_identifier,
    relationship_hints,
    replace_identifier,
)


@pytest.mark.unit
def test_numeric_first_path_segment_does_not_double_slash() -> None:
    mutations = generate_all_mutations("https://example.com/42/profile")
    path_muts = [item for item in mutations if item["strategy"].startswith("numeric_path")]
    assert path_muts
    for item in path_muts:
        assert "example.com//" not in item["mutated_url"]
        assert "/42/" not in item["mutated_url"] or item["mutated_value"] == "42"
    incremented = next(item for item in path_muts if item["strategy"] == "numeric_path_increment")
    assert "/43/profile" in incremented["mutated_url"]


@pytest.mark.unit
def test_replace_identifier_replaces_whole_path_segment_only() -> None:
    url = "https://example.com/api/v10/users/10"
    updated = replace_identifier(url, "path", "10", "11", location="path")
    assert "/v10/" in updated
    assert "/users/11" in updated
    assert replace_identifier(url, "path", "99", "11", location="path") == ""


@pytest.mark.unit
def test_query_and_uuid_mutations() -> None:
    numeric = mutate_identifier("https://example.com/items?id=10&ref=x")
    assert numeric is not None
    assert numeric["strategy"] == "numeric_query_increment"
    assert "id=11" in numeric["mutated_url"]
    uuid_url = "https://example.com/users?uid=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    uuid_mut = mutate_identifier(uuid_url)
    assert uuid_mut is not None
    assert uuid_mut["strategy"] == "uuid_query_replace"
    all_muts = generate_all_mutations("https://example.com/users?id=7")
    assert {item["strategy"] for item in all_muts} >= {
        "numeric_query_increment",
        "numeric_query_zero",
    }


@pytest.mark.unit
def test_extract_learn_and_relationship_helpers() -> None:
    assert extract_path_identifier("/orders/99/edit")["kind"] == "numeric"
    assert extract_path_identifier("/x") is None
    assert learn_id_pattern("https://ex/u/1", [{"value": "12"}]) == "sequential_numeric"
    assert learn_id_pattern("https://ex/user-12", []) == "prefixed_numeric"
    hints = relationship_hints(
        "https://ex/x?user_id=1&account_id=2&resource_id=3",
        [{"value": "1"}, {"value": "2"}],
    )
    assert "user_to_account" in hints
    assert "multi_identifier_endpoint" in hints
    variants = bulk_mutations(
        "https://example.com/api/v10/users/10",
        [{"parameter": "path", "value": "10", "kind": "numeric", "location": "path"}],
    )
    assert variants
    assert all("/v10/" in item["mutated_url"] for item in variants)
    assert all("/users/10" not in item["mutated_url"] for item in variants)
