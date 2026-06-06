"""TOML-driven exit-code policy for CI/CD consumers.

The :class:`ExitConditionPolicy` reads a TOML file and produces an
:class:`PolicyEvaluation` that maps a pipeline outcome to one of the
documented exit codes (0, 2, 3, 4 — 1 is reserved for unclassified
errors and 130 for SIGINT).  Policies are intentionally declarative
so security engineers can version-control gating rules alongside the
pipeline config.

Example ``policy.toml``::

    [on_findings]
    max_critical = 0     # any critical finding fails the run
    max_high = 5         # up to 5 high-severity findings allowed
    max_medium = 50      # medium cap
    allow_false_positive = true   # ai_triage_decision = "FP" findings are excluded

    [on_failure]
    retryable_only = false        # false ⇒ all infra failures non-zero exit
    treat_partial_as = 4         # partial runs exit 4 instead of 0

    [on_infra]
    # Stage names whose failure counts as infra, not partial.
    fatal_stages = ["subdomains", "live_hosts", "urls"]
"""

from __future__ import annotations

import fnmatch
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER: tuple[str, ...] = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class SeverityThresholds:
    """Per-severity maximum counts.

    A severity is "in violation" when the count of reportable findings at
    or above that severity exceeds its configured maximum.  Counts are
    inclusive of higher severities: ``max_high = 5`` means "no more than
    5 findings of severity high *or critical* combined".
    """

    critical: int = 0
    high: int = 5
    medium: int = 50
    low: int = 1000

    def violations(self, counts: Mapping[str, int]) -> list[str]:
        out: list[str] = []
        if counts.get("critical", 0) > self.critical:
            out.append(
                f"critical={counts.get('critical', 0)} > max_critical={self.critical}"
            )
        if counts.get("high", 0) + counts.get("critical", 0) > self.high:
            out.append(
                f"high+critical={counts.get('high', 0) + counts.get('critical', 0)} > max_high={self.high}"
            )
        if (
            counts.get("medium", 0)
            + counts.get("high", 0)
            + counts.get("critical", 0)
            > self.medium
        ):
            out.append(
                "medium+high+critical="
                f"{counts.get('medium', 0) + counts.get('high', 0) + counts.get('critical', 0)}"
                f" > max_medium={self.medium}"
            )
        if (
            counts.get("low", 0)
            + counts.get("medium", 0)
            + counts.get("high", 0)
            + counts.get("critical", 0)
            > self.low
        ):
            out.append(
                "total="
                f"{counts.get('low', 0) + counts.get('medium', 0) + counts.get('high', 0) + counts.get('critical', 0)}"
                f" > max_low={self.low}"
            )
        return out


@dataclass(frozen=True)
class FindingsRule:
    """``[on_findings]`` block — gates the run on finding severity counts."""

    thresholds: SeverityThresholds = field(default_factory=SeverityThresholds)
    allow_false_positive: bool = True
    exclude_categories: frozenset[str] = field(default_factory=frozenset)
    branch_glob: str = "*"

    def matches_branch(self, branch: str) -> bool:
        if not branch or self.branch_glob == "*":
            return True
        return fnmatch.fnmatchcase(branch, self.branch_glob)


@dataclass(frozen=True)
class InfraRule:
    """``[on_infra]`` block — which stages count as infrastructure."""

    fatal_stages: frozenset[str] = field(
        default_factory=lambda: frozenset({"subdomains", "live_hosts", "urls"})
    )


@dataclass(frozen=True)
class PolicyOnFailure:
    """``[on_failure]`` block — how to classify failed but non-fatal runs."""

    retryable_only: bool = False
    treat_partial_as: int = 4


@dataclass(frozen=True)
class ExitConditionPolicy:
    """Top-level policy document."""

    findings: FindingsRule = field(default_factory=FindingsRule)
    infra: InfraRule = field(default_factory=InfraRule)
    on_failure: PolicyOnFailure = field(default_factory=PolicyOnFailure)

    def to_dict(self) -> dict[str, Any]:
        return {
            "on_findings": {
                "max_critical": self.findings.thresholds.critical,
                "max_high": self.findings.thresholds.high,
                "max_medium": self.findings.thresholds.medium,
                "max_low": self.findings.thresholds.low,
                "allow_false_positive": self.findings.allow_false_positive,
                "exclude_categories": sorted(self.findings.exclude_categories),
                "branch_glob": self.findings.branch_glob,
            },
            "on_infra": {"fatal_stages": sorted(self.infra.fatal_stages)},
            "on_failure": {
                "retryable_only": self.on_failure.retryable_only,
                "treat_partial_as": self.on_failure.treat_partial_as,
            },
        }


DEFAULT_POLICY = ExitConditionPolicy()


class PolicyLoadError(ValueError):
    """Raised when a policy TOML cannot be parsed or is structurally invalid."""


def load_policy(path: str | Path | None) -> ExitConditionPolicy:
    """Load and validate a policy TOML file.

    Passing ``None`` returns :data:`DEFAULT_POLICY`.  Errors surface as
    :class:`PolicyLoadError` so callers can decide whether to fail the
    pre-flight (recommended) or fall back to defaults.
    """
    if path is None:
        return DEFAULT_POLICY
    p = Path(path)
    if not p.is_file():
        raise PolicyLoadError(f"Policy file not found: {p}")
    try:
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyLoadError(f"Failed to parse policy TOML {p}: {exc}") from exc
    return _from_mapping(data)


def _as_int(value: Any, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyLoadError(
            f"Policy field '{field_name}' must be an integer, got {type(value).__name__}"
        )
    if value < 0:
        raise PolicyLoadError(f"Policy field '{field_name}' must be non-negative, got {value}")
    return value


def _as_str(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise PolicyLoadError(
            f"Policy field '{field_name}' must be a string, got {type(value).__name__}"
        )
    return value


def _as_bool(value: Any, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyLoadError(
            f"Policy field '{field_name}' must be a boolean, got {type(value).__name__}"
        )
    return value


def _as_str_set(value: Any, *, field_name: str) -> frozenset[str]:
    if not isinstance(value, (list, tuple)):
        raise PolicyLoadError(
            f"Policy field '{field_name}' must be a list of strings, got {type(value).__name__}"
        )
    out: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise PolicyLoadError(
                f"Policy field '{field_name}' entries must be strings, got {type(item).__name__}"
            )
        out.add(item)
    return frozenset(out)


def _from_mapping(data: Mapping[str, Any]) -> ExitConditionPolicy:
    if not isinstance(data, Mapping):
        raise PolicyLoadError(
            f"Policy root must be a table, got {type(data).__name__}"
        )

    findings_block = data.get("on_findings", {}) or {}
    if not isinstance(findings_block, Mapping):
        raise PolicyLoadError("'on_findings' must be a table")

    thresholds = SeverityThresholds(
        critical=_as_int(findings_block.get("max_critical", 0), field_name="max_critical"),
        high=_as_int(findings_block.get("max_high", 5), field_name="max_high"),
        medium=_as_int(findings_block.get("max_medium", 50), field_name="max_medium"),
        low=_as_int(findings_block.get("max_low", 1000), field_name="max_low"),
    )
    findings = FindingsRule(
        thresholds=thresholds,
        allow_false_positive=_as_bool(
            findings_block.get("allow_false_positive", True),
            field_name="allow_false_positive",
        ),
        exclude_categories=_as_str_set(
            findings_block.get("exclude_categories", []),
            field_name="exclude_categories",
        ),
        branch_glob=_as_str(findings_block.get("branch_glob", "*"), field_name="branch_glob"),
    )

    infra_block = data.get("on_infra", {}) or {}
    if not isinstance(infra_block, Mapping):
        raise PolicyLoadError("'on_infra' must be a table")
    infra = InfraRule(
        fatal_stages=_as_str_set(
            infra_block.get("fatal_stages", ["subdomains", "live_hosts", "urls"]),
            field_name="fatal_stages",
        ),
    )

    failure_block = data.get("on_failure", {}) or {}
    if not isinstance(failure_block, Mapping):
        raise PolicyLoadError("'on_failure' must be a table")
    on_failure = PolicyOnFailure(
        retryable_only=_as_bool(
            failure_block.get("retryable_only", False), field_name="retryable_only"
        ),
        treat_partial_as=_as_int(
            failure_block.get("treat_partial_as", 4), field_name="treat_partial_as"
        ),
    )
    if on_failure.treat_partial_as not in (0, 2, 4):
        raise PolicyLoadError(
            f"on_failure.treat_partial_as must be 0, 2 or 4 (got {on_failure.treat_partial_as})"
        )

    return ExitConditionPolicy(findings=findings, infra=infra, on_failure=on_failure)


def _is_false_positive(finding: Mapping[str, Any]) -> bool:
    if str(finding.get("lifecycle_state", "")).upper() == "FALSE_POSITIVE":
        return True
    if str(finding.get("status", "")).lower() == "false_positive":
        return True
    decision = finding.get("ai_triage_decision")
    return isinstance(decision, str) and decision.upper() == "FP"


def _count_findings(
    findings: Sequence[Mapping[str, Any]],
    *,
    allow_false_positive: bool,
    exclude_categories: Iterable[str],
) -> dict[str, int]:
    excluded = {c.lower() for c in exclude_categories}
    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        if allow_false_positive and _is_false_positive(f):
            continue
        category = str(f.get("category", "")).lower()
        if category in excluded:
            continue
        severity = str(f.get("severity", "low")).lower()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


@dataclass(frozen=True)
class PolicyEvaluation:
    """Structured result of a policy evaluation.

    The orchestrator emits this on the event bus as
    :attr:`EventType.INGRESS_POLICY_RESULT`; CI runners consume the
    ``exit_code`` field while dashboards and audit subscribers
    consume the rest.
    """

    exit_code: int
    outcome: str
    counts: dict[str, int] = field(default_factory=dict)
    violations: list[str] = field(default_factory=list)
    failed_stages: tuple[str, ...] = ()
    partial: bool = False
    branch: str = ""
    policy_snapshot: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "outcome": self.outcome,
            "counts": dict(self.counts),
            "violations": list(self.violations),
            "failed_stages": list(self.failed_stages),
            "partial": self.partial,
            "branch": self.branch,
            "policy_snapshot": dict(self.policy_snapshot),
        }


def evaluate_policy(
    policy: ExitConditionPolicy,
    *,
    findings: Sequence[Mapping[str, Any]],
    failed_stages: Mapping[str, Mapping[str, Any]],
    branch: str = "",
) -> PolicyEvaluation:
    """Classify a pipeline outcome against ``policy``.

    Args:
        policy: Loaded :class:`ExitConditionPolicy` (or :data:`DEFAULT_POLICY`).
        findings: List of normalized finding dicts (each must expose at
            minimum ``severity`` and ``category``).
        failed_stages: Mapping of stage name → metrics dict for any stage
            whose status is not COMPLETED.  The function inspects the
            ``fatal`` flag and the configured ``infra.fatal_stages`` set
            to decide whether each entry counts as infra or partial.
        branch: Git branch name (used for ``[on_findings] branch_glob``
            filtering).  Empty string is treated as ``"*"`` (always match).
    """
    failed_stage_names = tuple(sorted(failed_stages.keys()))
    infra_failures = sorted(
        name
        for name, metrics in failed_stages.items()
        if name in policy.infra.fatal_stages or bool(metrics.get("fatal", False))
    )
    partial_failures = sorted(set(failed_stage_names) - set(infra_failures))

    if infra_failures:
        return PolicyEvaluation(
            exit_code=3,
            outcome="infra_failure",
            failed_stages=tuple(infra_failures),
            branch=branch,
            policy_snapshot=policy.to_dict(),
        )

    counts = _count_findings(
        findings,
        allow_false_positive=policy.findings.allow_false_positive,
        exclude_categories=policy.findings.exclude_categories,
    )

    if policy.findings.matches_branch(branch):
        violations = policy.findings.thresholds.violations(counts)
        if violations:
            return PolicyEvaluation(
                exit_code=2,
                outcome="policy_violation",
                counts=counts,
                violations=violations,
                failed_stages=failed_stage_names,
                branch=branch,
                policy_snapshot=policy.to_dict(),
            )

    if partial_failures:
        return PolicyEvaluation(
            exit_code=policy.on_failure.treat_partial_as,
            outcome="partial",
            counts=counts,
            failed_stages=tuple(partial_failures),
            partial=True,
            branch=branch,
            policy_snapshot=policy.to_dict(),
        )

    return PolicyEvaluation(
        exit_code=0,
        outcome="pass",
        counts=counts,
        failed_stages=(),
        branch=branch,
        policy_snapshot=policy.to_dict(),
    )
