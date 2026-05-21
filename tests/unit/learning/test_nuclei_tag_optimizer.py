"""Unit tests for NucleiTagOptimizer."""

import pytest
from unittest.mock import MagicMock
from src.learning.nuclei_tag_optimizer import NucleiTagOptimizer
from src.learning.telemetry_store import TelemetryStore

@pytest.fixture
def mock_store():
    store = MagicMock(spec=TelemetryStore)
    return store

def test_optimize_adaptive_tags_no_events(mock_store):
    mock_store.get_feedback_events.return_value = []
    optimizer = NucleiTagOptimizer(mock_store)
    
    current_tags = {"api": ["api", "exposure"]}
    optimized = optimizer.optimize_adaptive_tags(current_tags)
    
    assert optimized == current_tags

def test_optimize_adaptive_tags_demote_noisy(mock_store):
    # Simulate events where 'exposure' tag on 'api' endpoint type is noisy (all FPs)
    events = [
        {
            "plugin_name": "nuclei",
            "endpoint_type": "api",
            "finding_category": "http/exposures/token.yaml",
            "was_validated": False,
            "was_false_positive": True
        }
    ] * 5
    
    mock_store.get_feedback_events.return_value = events
    optimizer = NucleiTagOptimizer(mock_store)
    
    current_tags = {"api": ["api", "exposure"]}
    # 'api' should stay, 'exposure' should be removed because it was active for all these FPs
    optimized = optimizer.optimize_adaptive_tags(current_tags, fp_threshold=0.7, min_events=3)
    
    assert "exposure" not in optimized["api"]
    assert "api" in optimized["api"]

def test_optimize_adaptive_tags_keep_good(mock_store):
    # Simulate events where 'api' tag is performing well (all TPs)
    events = [
        {
            "plugin_name": "nuclei",
            "endpoint_type": "api",
            "finding_category": "http/vulnerabilities/api/token.yaml",
            "was_validated": True,
            "was_false_positive": False
        }
    ] * 5
    
    mock_store.get_feedback_events.return_value = events
    optimizer = NucleiTagOptimizer(mock_store)
    
    current_tags = {"api": ["api"]}
    optimized = optimizer.optimize_adaptive_tags(current_tags)
    
    assert optimized == current_tags
