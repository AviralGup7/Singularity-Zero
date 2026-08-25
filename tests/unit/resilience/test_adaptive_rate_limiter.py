import time
import unittest

from src.resilience.adaptive_rate_limiter import AdaptiveRateLimiter


class TestAdaptiveRateLimiter(unittest.TestCase):
    def test_aimd_concurrency_increase_and_decrease(self):
        limiter = AdaptiveRateLimiter(
            default_concurrency=4.0,
            min_concurrency=1.0,
            max_concurrency=8.0,
            multiplicative_decrease=0.5,
        )

        host = "api.target.com"

        # Initial concurrency
        self.assertEqual(limiter.get_allowed_concurrency(host), 4)

        # 5 successes trigger additive increase by 1.0 (4.0 -> 5.0)
        for _ in range(5):
            limiter.on_success(host)

        self.assertEqual(limiter.get_allowed_concurrency(host), 5)

        # Rate limit triggers multiplicative decrease by 0.5 (5.0 -> 2.5, int 2) and cooldown
        limiter.on_rate_limit(host, retry_after=1.0)
        self.assertTrue(limiter.is_backed_off(host))
        self.assertEqual(limiter.get_allowed_concurrency(host), 0)

        # After backoff expiry, allowed concurrency reflects reduced limit
        state = limiter._hosts[host]
        state.backoff_until = time.time() - 1.0
        self.assertFalse(limiter.is_backed_off(host))
        self.assertEqual(limiter.get_allowed_concurrency(host), 2)
