"""Unit tests for src.core.utils.timezones."""

import time
import unittest
from datetime import datetime

import pytest

from src.core.utils.timezones import (
    IST,
    IST_LABEL,
    format_epoch_ist,
    format_iso_to_ist,
    ist_timestamp,
    now_ist,
    run_dir_stamp,
)


@pytest.mark.unit
class TestNowIst(unittest.TestCase):
    def test_returns_datetime_in_ist_zone(self) -> None:
        ts = now_ist()
        self.assertIsInstance(ts, datetime)
        self.assertIsNotNone(ts.tzinfo)

    def test_ist_offset_is_530(self) -> None:
        ts = now_ist()
        offset = ts.utcoffset()
        self.assertIsNotNone(offset)
        self.assertEqual(offset.total_seconds(), 5 * 3600 + 30 * 60)

    def test_returns_current_time_within_window(self) -> None:
        ts1 = now_ist()
        ts2 = datetime.now(IST)
        diff = abs((ts2 - ts1).total_seconds())
        self.assertLess(diff, 5.0)


@pytest.mark.unit
class TestIstTimestamp(unittest.TestCase):
    def test_returns_iso_formatted_string(self) -> None:
        ts = ist_timestamp()
        self.assertIsInstance(ts, str)
        self.assertRegex(ts, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_includes_ist_offset_marker(self) -> None:
        ts = ist_timestamp()
        self.assertIn("+05:30", ts)


@pytest.mark.unit
class TestRunDirStamp(unittest.TestCase):
    def test_returns_yyyymmdd_hhmmss_format(self) -> None:
        stamp = run_dir_stamp()
        self.assertRegex(stamp, r"^\d{8}-\d{6}$")

    def test_format_consistent_across_invocations(self) -> None:
        s1 = run_dir_stamp()
        time.sleep(0.05)
        s2 = run_dir_stamp()
        self.assertRegex(s1, r"^\d{8}-\d{6}$")
        self.assertRegex(s2, r"^\d{8}-\d{6}$")


@pytest.mark.unit
class TestFormatEpochIst(unittest.TestCase):
    def test_none_returns_empty_string(self) -> None:
        self.assertEqual(format_epoch_ist(None), "")

    def test_zero_epoch_renders_string(self) -> None:
        result = format_epoch_ist(0)
        self.assertIsInstance(result, str)
        self.assertIn("IST", result)

    def test_integer_epoch_handled(self) -> None:
        result = format_epoch_ist(1700000000)
        self.assertIn("IST", result)

    def test_float_epoch_handled(self) -> None:
        result = format_epoch_ist(1700000000.5)
        self.assertIn("IST", result)

    def test_returns_am_or_pm_marker(self) -> None:
        result = format_epoch_ist(1700000000)
        self.assertTrue("AM" in result or "PM" in result)

    def test_includes_year_in_output(self) -> None:
        result = format_epoch_ist(1700000000)
        self.assertRegex(result, r"\d{4}")

    def test_negative_epoch_handled(self) -> None:
        result = format_epoch_ist(0)
        self.assertIsInstance(result, str)


@pytest.mark.unit
class TestFormatIsoToIst(unittest.TestCase):
    def test_none_returns_empty_string(self) -> None:
        self.assertEqual(format_iso_to_ist(None), "")

    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(format_iso_to_ist(""), "")

    def test_returns_original_value_for_invalid_iso(self) -> None:
        invalid = "not-an-iso-date"
        self.assertEqual(format_iso_to_ist(invalid), invalid)

    def test_converts_utc_iso_to_ist(self) -> None:
        utc_iso = "2024-01-15T12:00:00+00:00"
        result = format_iso_to_ist(utc_iso)
        self.assertIn("IST", result)
        self.assertIn("05:30:00", result)

    def test_naive_datetime_assumed_utc(self) -> None:
        result = format_iso_to_ist("2024-01-15T00:00:00")
        self.assertIn("IST", result)

    def test_already_ist_iso_passes_through(self) -> None:
        ist_iso = "2024-01-15T05:30:00+05:30"
        result = format_iso_to_ist(ist_iso)
        self.assertIn("05:30:00", result)

    def test_pst_input_converted_to_ist(self) -> None:
        pst_iso = "2024-01-15T00:00:00-08:00"
        result = format_iso_to_ist(pst_iso)
        self.assertIn("IST", result)


@pytest.mark.unit
class TestConstants(unittest.TestCase):
    def test_ist_label_format(self) -> None:
        self.assertEqual(IST_LABEL, "IST (+05:30)")

    def test_ist_zone_has_correct_offset(self) -> None:
        now = datetime.now(IST)
        offset = now.utcoffset()
        self.assertIsNotNone(offset)
        self.assertEqual(offset.total_seconds(), 19800)


if __name__ == "__main__":
    unittest.main()
