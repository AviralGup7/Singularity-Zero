import unittest
from src.infrastructure.flow_control.pid_controller import AdaptivePIDController, PIDTuning


class TestAdaptivePIDAntiWindup(unittest.TestCase):
    def test_anti_windup_under_sustained_overload(self) -> None:
        tuning = PIDTuning(
            kp=0.5,
            ki=0.1,
            kd=0.05,
            target_latency_ms=100.0,
            min_concurrency=1,
            max_concurrency=50,
            i_max=200.0,
        )
        pid = AdaptivePIDController(tuning=tuning)

        # Simulate sustained overload: 100 observations with 5000ms latency and errors
        for _ in range(100):
            pid.observe(observed_latency_ms=5000.0, error_occurred=True)

        # Controller should clamp concurrency to min (1)
        self.assertEqual(pid.current_concurrency, 1)
        # Integral term must not blow up beyond bound i_max
        self.assertGreaterEqual(pid.integral, -200.0)
        self.assertLessEqual(pid.integral, 200.0)

        # Target recovers immediately to fast 50ms latency
        # Anti-windup ensures we do not stay stuck at min_concurrency for dozens of ticks
        recovered_concurrency, _ = pid.observe(observed_latency_ms=50.0, error_occurred=False)
        self.assertGreaterEqual(recovered_concurrency, 1)

    def test_reset_integral(self) -> None:
        pid = AdaptivePIDController()
        pid.observe(5000.0, True)
        self.assertNotEqual(pid.integral, 0.0)
        pid.reset_integral()
        self.assertEqual(pid.integral, 0.0)


if __name__ == "__main__":
    unittest.main()
