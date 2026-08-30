"""B15: MemoryJournal is test-only."""

from __future__ import annotations

import os
import unittest


class TestMemoryJournalProduction(unittest.TestCase):
    def test_refuses_production_env(self) -> None:
        old = os.environ.get("APP_ENV")
        try:
            os.environ["APP_ENV"] = "production"
            from src.frontier.journal import MemoryJournal

            with self.assertRaises(RuntimeError):
                MemoryJournal()
        finally:
            if old is None:
                os.environ.pop("APP_ENV", None)
            else:
                os.environ["APP_ENV"] = old

    def test_allowed_in_development(self) -> None:
        old = os.environ.get("APP_ENV")
        try:
            os.environ["APP_ENV"] = "development"
            from src.frontier.journal import MemoryJournal

            journal = MemoryJournal()
            self.assertEqual(len(journal), 0)
        finally:
            if old is None:
                os.environ.pop("APP_ENV", None)
            else:
                os.environ["APP_ENV"] = old


if __name__ == "__main__":
    unittest.main()
