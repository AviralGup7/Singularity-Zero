"""Centralized constants for the security testing pipeline.

This module consolidates magic numbers, thresholds, and configuration
constants that were previously scattered across multiple modules.
Using these constants instead of inline values enables:
- Centralized tuning without code changes
- Documentation of rationale for each value
- Consistent defaults across modules
"""

# =============================================================================
# Pipeline Orchestration
# =============================================================================

# Maximum number of iterative scanning rounds before forced termination
MAX_ITERATION_LIMIT = 5

# Maximum number of feedback URLs to add per iteration
FEEDBACK_URL_LIMIT = 30

# Confidence drop threshold for quality degradation detection (0.0-1.0)
CONFIDENCE_DEGRADATION_THRESHOLD = 0.85

# Minimum new findings required to continue despite confidence drop
MIN_NEW_FINDINGS_FOR_CONTINUE = 2

# Number of consecutive zero-finding iterations before stopping
CONVERGENCE_ITERATIONS = 2

# =============================================================================
# Severity Scoring
# =============================================================================

SEVERITY_SCORES = {
    "critical": 100,
    "high": 80,
    "medium": 55,
    "low": 30,
    "info": 15,
}

SEVERITY_PRIORITY_SCORES = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
}

# =============================================================================
# Analysis Engine
# =============================================================================

# Default timeout per analyzer in seconds
DEFAULT_ANALYZER_TIMEOUT_SECONDS = 60

# Default max workers for parallel analyzer execution
DEFAULT_ANALYZER_MAX_WORKERS = 4

# =============================================================================
# Screenshot Capture
# =============================================================================

# Default max concurrent screenshot workers
DEFAULT_SCREENSHOT_MAX_WORKERS = 4

# Default max hosts to screenshot
DEFAULT_SCREENSHOT_MAX_HOSTS = 25

# Default per-URL screenshot timeout in seconds
DEFAULT_SCREENSHOT_TIMEOUT_SECONDS = 20

# Default window size for screenshots
DEFAULT_SCREENSHOT_WINDOW_SIZE = "1440,900"

# =============================================================================
# Retry & Backoff
# =============================================================================

# Default jitter factor for retry backoff (0.0-1.0)
DEFAULT_RETRY_JITTER_FACTOR = 0.25

# =============================================================================
# CORS & Security
# =============================================================================

# Default allowed CORS origins for dashboard
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# =============================================================================
# Scoring & Classification
# =============================================================================

# Scan quality metric weights (must sum to 1.0)
SCAN_QUALITY_WEIGHTS = {
    "module_coverage": 0.3,
    "validation_coverage": 0.3,
    "high_confidence_pct": 0.2,
    "intelligence_coverage": 0.2,
}

# =============================================================================
# Health Score
# =============================================================================

# Multipliers for pipeline health score calculation
HEALTH_SCORE_MULTIPLIERS = {
    "critical": 15,
    "high": 8,
    "medium": 3,
}
