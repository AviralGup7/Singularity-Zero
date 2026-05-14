from src.analysis.accelerated_matcher import RegexPatternMatcher, create_pattern_matcher


def test_regex_pattern_matcher_finds_named_matches() -> None:
    matcher = RegexPatternMatcher(
        {
            "cloudflare": r"cloudflare",
            "secret": r"api[_-]?key",
        }
    )

    matches = matcher.scan("Blocked by Cloudflare; leaked api_key value")

    assert [match.pattern_id for match in matches] == ["cloudflare", "secret"]


def test_pattern_matcher_falls_back_without_acceleration() -> None:
    matcher = create_pattern_matcher({"token": r"bearer\s+[a-z]+"}, prefer_acceleration=False)

    assert isinstance(matcher, RegexPatternMatcher)
    assert matcher.scan("Bearer abc")[0].pattern_id == "token"
