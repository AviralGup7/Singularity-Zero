from pathlib import Path
from src.learning.telemetry_store import TelemetryStore



class TestTelemetryStoreInit:
    """Tests for TelemetryStore initialization."""

    def test_creates_database(self, tmp_db_path):
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        assert tmp_db_path.exists()
        store.close()

    def test_creates_parent_directory(self, tmp_path):
        db_path = tmp_path / "subdir" / "telemetry.db"
        store = TelemetryStore(db_path)
        store.initialize()
        assert db_path.exists()
        store.close()

    def test_default_path(self):
        store = TelemetryStore()
        assert store.db_path.name == "telemetry.db"
        assert store.db_path.parent.name == ".pipeline"

    def test_context_manager(self, tmp_db_path):
        with TelemetryStore(tmp_db_path) as store:
            assert store._initialized is True

    def test_idempotent_initialize(self, tmp_db_path):
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        store.initialize()
        assert store._initialized is True
        store.close()

    def test_close_is_idempotent(self, tmp_db_path):
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        store.close()
        store.close()

    def test_accepts_string_path(self, tmp_path):
        db_path = str(tmp_path / "str_path.db")
        store = TelemetryStore(db_path)
        store.initialize()
        assert Path(db_path).exists()
        store.close()