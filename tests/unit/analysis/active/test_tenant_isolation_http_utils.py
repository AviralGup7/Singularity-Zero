from src.analysis._core.http_request import _safe_request as core_safe_request
from src.analysis.active.tenant_isolation.http_utils import _safe_request


def test_tenant_isolation_http_utils_re_exports_safe_request() -> None:
    assert _safe_request is core_safe_request
