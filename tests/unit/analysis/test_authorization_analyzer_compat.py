from src.analysis.automation import access_control as automation_access_control
from src.analysis.checks.active import authorization_analyzer


def test_legacy_authorization_analyzer_reexports_canonical_classes() -> None:
    assert (
        authorization_analyzer.AccessControlAnalyzer
        is automation_access_control.AccessControlAnalyzer
    )
    assert authorization_analyzer.EnforcementResult is automation_access_control.EnforcementResult


def test_legacy_access_control_analyzer_exposes_sync_and_async_entrypoints() -> None:
    analyzer = authorization_analyzer.AccessControlAnalyzer(http_client=None)

    assert hasattr(analyzer, "analyze_endpoints")
    assert hasattr(analyzer, "check_endpoints")
