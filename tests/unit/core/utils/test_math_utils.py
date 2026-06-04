"""Unit tests for src.core.utils.math_utils."""

import unittest

import pytest

from src.core.utils.math_utils import clamp


@pytest.mark.unit
class TestClamp(unittest.TestCase):
    def test_returns_value_when_within_default_bounds(self) -> None:
        self.assertEqual(clamp(0.5), 0.5)

    def test_clamps_to_lower_default_bound(self) -> None:
        self.assertEqual(clamp(-0.5), 0.0)

    def test_clamps_to_upper_default_bound(self) -> None:
        self.assertEqual(clamp(1.5), 1.0)

    def test_zero_is_within_default_range(self) -> None:
        self.assertEqual(clamp(0.0), 0.0)

    def test_one_is_within_default_range(self) -> None:
        self.assertEqual(clamp(1.0), 1.0)

    def test_custom_lower_bound_applied(self) -> None:
        self.assertEqual(clamp(-5.0, low=-2.0, high=2.0), -2.0)

    def test_custom_upper_bound_applied(self) -> None:
        self.assertEqual(clamp(5.0, low=-2.0, high=2.0), 2.0)

    def test_value_within_custom_bounds_unchanged(self) -> None:
        self.assertEqual(clamp(1.5, low=-2.0, high=2.0), 1.5)

    def test_works_with_integer_inputs(self) -> None:
        self.assertEqual(clamp(10, low=0, high=5), 5)

    def test_bounds_equal_value_returns_bound(self) -> None:
        self.assertEqual(clamp(5.0, low=5.0, high=5.0), 5.0)

    def test_negative_bounds(self) -> None:
        self.assertEqual(clamp(-1.0, low=-3.0, high=-2.0), -2.0)

    def test_floating_point_precision(self) -> None:
        self.assertAlmostEqual(clamp(0.123456789), 0.123456789, places=6)

    def test_string_input_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            clamp("not a number")  # type: ignore[arg-type]

    def test_returns_float_type(self) -> None:
        result = clamp(1)
        self.assertIsInstance(result, float)


if __name__ == "__main__":
    unittest.main()
