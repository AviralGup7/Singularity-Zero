"""HTML report generation utilities.

Provides CSS styles, JavaScript assets, and page generation functions
for building pipeline run reports and dashboard index pages.
"""

from src.reporting.assets import INDEX_STYLES, REPORT_SCRIPT, RUN_REPORT_STYLES
from src.reporting.pages import build_dashboard_index, generate_run_report

__all__ = [
    "RUN_REPORT_STYLES",
    "REPORT_SCRIPT",
    "INDEX_STYLES",
    "generate_run_report",
    "build_dashboard_index",
]
