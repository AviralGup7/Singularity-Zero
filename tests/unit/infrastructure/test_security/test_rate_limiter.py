import os
import sys

from src.infrastructure.security.rate_limiter import (
    RateLimiter,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestRateLimiter(SecurityTestBase):
    def test_default_limit(self) -> None:
        limiter = RateLimiter(self.security_config)
        result = limiter.check_rate_limit("192.168.1.1")
        assert result.allowed is True

    def test_bypass_token(self) -> None:
        self.security_config.rate_limit.bypass_tokens = ["internal-token"]
        limiter = RateLimiter(self.security_config)
        result = limiter.check_rate_limit("192.168.1.1", bypass_token="internal-token")
        assert result.allowed is True
        assert result.limit == 999999

    def test_set_endpoint_limit(self) -> None:
        limiter = RateLimiter(self.security_config)
        limiter.set_endpoint_limit("/api/custom", 5)
        for _ in range(5):
            limiter.check_rate_limit("1.2.3.4", endpoint="/api/custom")
        result = limiter.check_rate_limit("1.2.3.4", endpoint="/api/custom")
        assert result.allowed is False

    def test_add_remove_bypass_token(self) -> None:
        limiter = RateLimiter(self.security_config)
        limiter.add_bypass_token("new-token")
        result = limiter.check_rate_limit("1.2.3.4", bypass_token="new-token")
        assert result.allowed is True
        assert limiter.remove_bypass_token("new-token") is True
        assert limiter.remove_bypass_token("nonexistent") is False

    def test_cleanup(self) -> None:
        limiter = RateLimiter(self.security_config)
        limiter.check_rate_limit("1.2.3.4")
        removed = limiter.cleanup()
        assert removed >= 0
