from collections.abc import Callable
from dataclasses import dataclass

from .advanced import advanced_api_key_test
from .detailed import detailed_api_key_test
from .scope import subdomain_privilege_methods_test
from .write_actions import write_flexible_chaining_test


@dataclass(frozen=True)
class ApiKeyWorkflowSpec:
    key: str
    label: str
    description: str
    runner: Callable[..., object]


WORKFLOW_SPECS = (
    ApiKeyWorkflowSpec(
        key="advanced",
        label="Advanced API Key Test",
        description="Run the broad advanced API key coverage workflow.",
        runner=advanced_api_key_test,
    ),
    ApiKeyWorkflowSpec(
        key="detailed",
        label="Detailed API Key Test",
        description="Run the detailed key-placement and endpoint validation workflow.",
        runner=detailed_api_key_test,
    ),
    ApiKeyWorkflowSpec(
        key="scope",
        label="Scope And Privilege Workflow",
        description="Probe subdomain, privilege, and method scope behavior for exposed keys.",
        runner=subdomain_privilege_methods_test,
    ),
    ApiKeyWorkflowSpec(
        key="write_actions",
        label="Write Action Workflow",
        description="Probe whether the key permits write-oriented action chaining.",
        runner=write_flexible_chaining_test,
    ),
)

WORKFLOW_SPECS_BY_KEY = {spec.key: spec for spec in WORKFLOW_SPECS}


def list_workflows() -> tuple[ApiKeyWorkflowSpec, ...]:
    return WORKFLOW_SPECS


def get_workflow(key: str) -> ApiKeyWorkflowSpec:
    return WORKFLOW_SPECS_BY_KEY[key]


def get_workflow_runner(key: str) -> Callable[..., object]:
    return get_workflow(key).runner
