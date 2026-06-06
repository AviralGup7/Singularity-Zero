"""CI/CD integration services for the security testing pipeline.

Provides:

* :class:`ExitConditionPolicy` — declarative TOML-driven mapping from
  pipeline outcomes to CI exit codes.  Replaces the binary
  success/failure signal with a 5-value taxonomy (0/1/2/3/4) so CI
  consumers can distinguish "we found 12 criticals" (exit 2 — a
  successful pentest outcome) from "the network was unreachable"
  (exit 3 — an operational failure).

* :class:`PolicyEvaluation` — structured result of a policy evaluation
  that the orchestrator emits on the event bus as
  ``INGRESS_POLICY_RESULT`` for downstream policy engines.

Exit-code taxonomy (kept stable across versions):

    0  pass             — run completed, no policy violation
    1  error            — legacy/unclassified failure (kept for back-compat)
    2  policy_violation — findings exceeded declared policy thresholds
    3  infra_failure    — operational failure (network, missing tool, fatal recon)
    4  partial          — at least one non-fatal stage failed but the run produced
                          a usable report
   130  interrupted      — SIGINT / SIGTERM (matches POSIX convention)
"""

from .policy import (
    DEFAULT_POLICY,
    ExitConditionPolicy,
    FindingsRule,
    InfraRule,
    PolicyEvaluation,
    PolicyLoadError,
    PolicyOnFailure,
    SeverityThresholds,
    evaluate_policy,
    load_policy,
)

__all__ = [
    "DEFAULT_POLICY",
    "ExitConditionPolicy",
    "FindingsRule",
    "InfraRule",
    "PolicyEvaluation",
    "PolicyLoadError",
    "PolicyOnFailure",
    "SeverityThresholds",
    "evaluate_policy",
    "load_policy",
]
