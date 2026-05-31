"""Utility functions for the learning subsystem."""

def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    """Clamp a value between low and high bounds."""
    return max(low, min(high, value))
