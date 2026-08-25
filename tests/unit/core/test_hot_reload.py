"""Unit tests for the Target Hot-Reload & Scan Suspend/Resume Manager."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.core.hot_reload import HotReloadManager


def test_hot_reload_manager_flow():
    """Verify that HotReloadManager triggers, checks, and clears suspend files correctly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir)
        manager = HotReloadManager(output_path)

        target = "test-target.example.com"
        stage = "vulnerabilities"

        # Initially, no suspend should be triggered
        assert not manager.check_suspend_trigger(target, stage)

        # Trigger a suspend
        manager.trigger_suspend(target)

        # Suspend check should now be positive
        assert manager.check_suspend_trigger(target, stage)

        # Verify the flag file is indeed created
        flag_path = manager._get_flag_path(target)
        assert flag_path.exists()

        # Clear the suspend flag
        manager.clear_suspend(target)

        # Suspend check should now be negative
        assert not manager.check_suspend_trigger(target, stage)
        assert not flag_path.exists()
