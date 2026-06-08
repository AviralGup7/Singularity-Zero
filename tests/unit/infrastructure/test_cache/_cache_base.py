import tempfile
import unittest


class CacheTestBase(unittest.TestCase):
    def setUp(self) -> None:
        from pathlib import Path

        self.tmp_path = Path(tempfile.mkdtemp())
