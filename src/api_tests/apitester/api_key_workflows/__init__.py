from .registry import (
    WORKFLOW_SPECS,
    WORKFLOW_SPECS_BY_KEY,
    get_workflow,
    get_workflow_runner,
    list_workflows,
)

advanced_api_key_test = WORKFLOW_SPECS_BY_KEY["advanced"].runner
detailed_api_key_test = WORKFLOW_SPECS_BY_KEY["detailed"].runner
subdomain_privilege_methods_test = WORKFLOW_SPECS_BY_KEY["scope"].runner
write_flexible_chaining_test = WORKFLOW_SPECS_BY_KEY["write_actions"].runner

__all__ = [
    "WORKFLOW_SPECS",
    "WORKFLOW_SPECS_BY_KEY",
    "advanced_api_key_test",
    "detailed_api_key_test",
    "get_workflow",
    "get_workflow_runner",
    "list_workflows",
    "subdomain_privilege_methods_test",
    "write_flexible_chaining_test",
]
