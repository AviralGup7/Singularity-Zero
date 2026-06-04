"""Unit tests for src.analysis.sqli_signals."""

import unittest

import pytest

from src.analysis.sqli_signals import SQL_ERROR_RE, SQL_PARAM_NAMES


@pytest.mark.unit
class TestSqlParamNames(unittest.TestCase):
    def test_is_set(self) -> None:
        self.assertIsInstance(SQL_PARAM_NAMES, set)

    def test_contains_expected_common_params(self) -> None:
        for name in ("id", "user_id", "search", "query", "q"):
            self.assertIn(name, SQL_PARAM_NAMES)

    def test_contains_db_related_params(self) -> None:
        for name in ("sql", "db", "table", "raw", "native_query"):
            self.assertIn(name, SQL_PARAM_NAMES)

    def test_contains_odata_filter(self) -> None:
        self.assertIn("$filter", SQL_PARAM_NAMES)

    def test_minimum_param_count(self) -> None:
        self.assertGreaterEqual(len(SQL_PARAM_NAMES), 20)

    def test_no_empty_strings(self) -> None:
        self.assertNotIn("", SQL_PARAM_NAMES)

    def test_all_entries_lowercase(self) -> None:
        for name in SQL_PARAM_NAMES:
            self.assertEqual(name, name.lower(), f"{name} is not lowercase")


@pytest.mark.unit
class TestSqlErrorRegex(unittest.TestCase):
    def test_matches_mysql_error(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("You have an error in your SQL syntax"))

    def test_matches_postgres_error(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("psycopg2.errors.UndefinedColumn"))

    def test_matches_oracle_error(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("ORA-00933: SQL command not properly ended"))

    def test_matches_sqlstate(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("SQLSTATE[42000]"))

    def test_matches_unclosed_quotation(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("unclosed quotation mark"))

    def test_matches_unterminated_string(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("unterminated string literal"))

    def test_matches_syntax_error(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("syntax error at or near"))

    def test_matches_duplicate_key(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("duplicate key violation: foo"))

    def test_matches_integrity_constraint(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("integrity constraint violated"))

    def test_matches_foreign_key(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("foreign key constraint failed"))

    def test_matches_sqlite_error(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("sqlite3.OperationalError: no such table"))

    def test_matches_stack_trace(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("Traceback (most recent call last)"))

    def test_does_not_match_clean_text(self) -> None:
        self.assertIsNone(SQL_ERROR_RE.search("Hello, this is a normal response."))

    def test_does_not_match_html_only(self) -> None:
        self.assertIsNone(SQL_ERROR_RE.search("<html><body>OK</body></html>"))

    def test_is_case_insensitive(self) -> None:
        self.assertIsNotNone(SQL_ERROR_RE.search("SQL SYNTAX error"))
        self.assertIsNotNone(SQL_ERROR_RE.search("syntax ERROR"))

    def test_can_be_combined_with_other_text(self) -> None:
        combined = SQL_ERROR_RE.search("SELECT * FROM users; ORA-01403: no data found")
        self.assertIsNotNone(combined)


if __name__ == "__main__":
    unittest.main()
