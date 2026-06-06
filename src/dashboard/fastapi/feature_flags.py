"""Shim for feature flags under fastapi package to support backwards-compatible imports."""
from src.dashboard.feature_flags import FeatureFlags

__all__ = ["FeatureFlags"]
