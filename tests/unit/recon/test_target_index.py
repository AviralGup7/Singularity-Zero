import pytest

from src.recon.target_index import ParsedUrl, TargetIndex, format_ipv4_fast, parse_ipv4_fast


class TestIPv4Fast:
    @pytest.mark.parametrize(
        "ip_str, expected_success, expected_int",
        [
            ("127.0.0.1", True, 0x7F000001),
            ("192.168.1.1", True, 0xC0A80101),
            ("255.255.255.255", True, 0xFFFFFFFF),
            ("0.0.0.0", True, 0x00000000),  # noqa: S104
            ("10.0.0.255", True, 0x0A0000FF),
            # Invalid IPs
            ("256.0.0.1", False, 0),
            ("127.0.0", False, 0),
            ("127.0.0.1.1", False, 0),
            ("127.0.a.1", False, 0),
            ("...", False, 0),
            ("1.2.3.4.", False, 0),
            (".1.2.3.4", False, 0),
            ("127..0.1", False, 0),
            ("", False, 0),
            ("999.999.999.999", False, 0),
        ],
    )
    def test_parse_ipv4_fast(self, ip_str, expected_success, expected_int):
        success, ip_int = parse_ipv4_fast(ip_str)
        assert success == expected_success
        assert ip_int == expected_int

    @pytest.mark.parametrize(
        "ip_int, expected_str",
        [
            (0x7F000001, "127.0.0.1"),
            (0xC0A80101, "192.168.1.1"),
            (0xFFFFFFFF, "255.255.255.255"),
            (0x00000000, "0.0.0.0"),  # noqa: S104
        ],
    )
    def test_format_ipv4_fast(self, ip_int, expected_str):
        assert format_ipv4_fast(ip_int) == expected_str


class TestParsedUrl:
    def test_parse_basic_url(self):
        url = "https://example.com/api/v1/users?id=123"
        p = ParsedUrl.parse(url)
        assert p.url == url
        assert p.hostname == "example.com"
        assert p.scheme == "https"
        assert p.path == "/api/v1/users"
        assert "id" in p.query_params
        assert p.has_id_param is True
        assert p.has_url_param is False
        assert p.path_segments == ["api", "v1", "users"]
        assert p.risk_score > 0
        assert p.is_ipv4() is False

    def test_parse_ipv4_url(self):
        url = "http://1.2.3.4/admin"
        p = ParsedUrl.parse(url)
        assert p.hostname == "1.2.3.4"
        assert p.hostname_ip == 0x01020304
        assert p.is_ipv4() is True
        assert "admin" in p.path_segments
        assert p.risk_score >= 4.0  # admin boost

    def test_parse_url_param(self):
        url = "https://example.com/redirect?dest=https://evil.com"
        p = ParsedUrl.parse(url)
        assert p.has_url_param is True
        assert p.risk_score >= 3.0  # url param boost

    def test_parse_invalid_url(self):
        # urlparse doesn't easily fail, but we can try something weird
        url = "not-a-url"
        p = ParsedUrl.parse(url)
        assert p.url == url
        # Should not crash

    def test_risk_scoring_combinations(self):
        # Admin + API + ID
        url = "https://example.com/api/admin/users?user_id=456"
        p = ParsedUrl.parse(url)
        # ID(2) + PathAdmin(4) + PathAPI(1) + Query(1) + Segments(0.5) = 8.5
        assert p.risk_score >= 8.5

        # Upload + File
        url = "https://example.com/upload/file"
        p = ParsedUrl.parse(url)
        # Upload/File(1.5) + Segments(0.5) = 2.0
        assert p.risk_score >= 2.0


class TestTargetIndex:
    @pytest.fixture
    def sample_urls(self):
        return [
            "https://127.0.0.1/status",
            "https://example.com/api/v1",
            "http://192.168.1.1/admin",
            "https://test.local/debug",
            "https://example.com/login?redirect=/dashboard",
        ]

    def test_build_index(self, sample_urls):
        index = TargetIndex.build(sample_urls)
        assert len(index.urls) == 5
        assert len(index.parsed) == 5
        assert len(index.ipv4_targets) == 2  # 127.0.0.1, 192.168.1.1
        assert len(index.hostname_targets) == 3  # example.com (x2), test.local

    def test_get_fast_paths(self, sample_urls):
        index = TargetIndex.build(sample_urls)
        fast = index.get_fast_paths()
        assert len(fast) == 5
        for idx, p in fast:
            assert isinstance(p, ParsedUrl)

    def test_get_by_host(self, sample_urls):
        index = TargetIndex.build(sample_urls)
        example_targets = index.get_by_host("example.com")
        assert len(example_targets) == 2
        assert all(p.hostname == "example.com" for p in example_targets)

    def test_get_risk_sorted(self, sample_urls):
        index = TargetIndex.build(sample_urls)
        sorted_targets = index.get_risk_sorted()
        assert len(sorted_targets) == 5
        # The admin one should be near the top
        assert "admin" in sorted_targets[0].path or "debug" in sorted_targets[0].path

    def test_get_stats(self, sample_urls):
        index = TargetIndex.build(sample_urls)
        stats = index.get_stats()
        assert stats["total_urls"] == 5
        assert stats["ipv4_targets"] == 2
        assert stats["hostname_targets"] == 3
        assert stats["avg_risk_score"] > 0
