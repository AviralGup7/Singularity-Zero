"""Cross-tenant PII exposure indicator spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("collection_like") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Compare the tenant, account, and user identifiers in the response and verify whether returned records cross an expected tenant boundary."


register_spec(
    (
        "cross_tenant_pii_risk_analyzer",
        "access_control",
        _severity,
        "Cross-tenant PII exposure indicator",
        _description,
    )
)
