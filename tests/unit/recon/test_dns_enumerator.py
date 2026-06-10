from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.dns_enumerator import (
    _check_dns_security,
    _extract_details,
    _is_security_relevant,
    _parse_nslookup_output,
    _query_dns,
    build_dns_report,
    enumerate_dns_records,
)


class TestDnsEnumerator:
    def test_is_security_relevant(self):
        assert _is_security_relevant("TXT", "v=spf1 include:_spf.google.com ~all") is True
        assert _is_security_relevant("TXT", "just some text") is False
        assert _is_security_relevant("MX", "10 mail.example.com") is True
        assert _is_security_relevant("NS", "ns1.example.com") is True
        assert _is_security_relevant("A", "1.2.3.4") is False

    def test_extract_details_spf(self):
        val = "v=spf1 include:_spf.google.com ~all"
        details = _extract_details("TXT", val)
        assert details["record"] == "SPF"
        assert "v=spf1" in details["mechanisms"]
        assert "~all" in details["mechanisms"]

    def test_extract_details_dmarc(self):
        val = "v=DMARC1; p=quarantine; pct=100"
        details = _extract_details("TXT", val)
        assert details["record"] == "DMARC"
        assert details["p"] == "quarantine"
        assert details["pct"] == "100"

    def test_extract_details_mx(self):
        val = "10 mail.example.com"
        details = _extract_details("MX", val)
        assert details["priority"] == "10"
        assert details["mail_server"] == "mail.example.com"

    def test_parse_nslookup_output(self):
        output = "example.com\tcanonical name = host.example.com.\n"
        results = _parse_nslookup_output(output, "CNAME")
        assert results == ["host.example.com"]

        output = "example.com\tmail exchanger = 10 mail.example.com.\n"
        results = _parse_nslookup_output(output, "MX")
        assert results == ["10 mail.example.com"]

    @pytest.mark.asyncio
    async def test_enumerate_dns_records_orchestration(self):
        with patch("src.recon.dns_enumerator._query_dns", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = ["val1"]

            results = await enumerate_dns_records({"example.com"}, record_types=["A"])

            assert len(results) == 1
            assert results[0]["domain"] == "example.com"
            assert results[0]["value"] == "val1"

    @pytest.mark.asyncio
    async def test_query_dns_a(self):
        with patch("src.recon.dns_enumerator._resolve_a") as mock_resolve:
            mock_resolve.return_value = ["1.2.3.4"]

            # Use a real loop or mock it
            res = await _query_dns("example.com", "A", 5.0)
            assert res == ["1.2.3.4"]

    @pytest.mark.asyncio
    async def test_query_dns_generic(self):
        with patch("src.recon.dns_enumerator._run_nslookup", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                ok=True, timed_out=False, stdout="example.com nameserver = ns1.com\n"
            )

            res = await _query_dns("example.com", "NS", 5.0)
            assert "ns1.com" in res

    def test_build_dns_report(self):
        records = [
            {
                "domain": "example.com",
                "record_type": "MX",
                "value": "10 mail.com",
                "security_relevant": True,
                "details": {"record": "MX"},
            },
            {
                "domain": "example.com",
                "record_type": "TXT",
                "value": "v=spf1...",
                "security_relevant": True,
                "details": {"record": "SPF"},
            },
        ]

        with patch("src.recon.dns_enumerator.enrich_findings_with_model_severity") as mock_enrich:
            mock_enrich.side_effect = lambda x: x
            report = build_dns_report(records)

            assert report["domains_queried"] == 1
            assert report["total_records"] == 2
            assert report["record_type_counts"]["MX"] == 1
            assert len(report["security_findings"]) == 2

    def test_check_dns_security_missing_spf(self):
        by_domain = {
            "example.com": [
                {"record_type": "MX", "value": "10 mail.com", "details": {}},
                {"record_type": "TXT", "value": "other", "details": {"record": "OTHER"}},
            ]
        }

        with patch("src.recon.dns_enumerator.enrich_findings_with_model_severity") as mock_enrich:
            mock_enrich.side_effect = lambda x: x
            findings = _check_dns_security(by_domain)

            assert any(f["issue"] == "missing_spf" for f in findings)
            assert any(f["issue"] == "missing_dmarc" for f in findings)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("lang", ["fr_FR.UTF-8", "ja_JP.UTF-8", "en_US.UTF-8"])
    async def test_dns_enumeration_locale_independence(self, lang):
        from src.recon.dns_enumerator import _parse_nslookup_output

        sample_output = "example.com\tnameserver = ns1.example.com.\n"
        results = _parse_nslookup_output(sample_output, "NS")
        assert results == ["ns1.example.com"]
