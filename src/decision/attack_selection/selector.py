from dataclasses import dataclass
from typing import Any

from src.core.contracts.pipeline import scope_match

_ActionSpec = dict[str, Any]
_PlannerConfig = dict[str, Any]

DEFAULT_SELECTOR_CONFIG: dict[str, Any] = {
    "planner": {
        "planner_enabled": True,
        "max_plans": 8,
    },
    "actions": {
        "ssrf_callback_probe": {
            "enabled": True,
            "base_score": 2,
            "requires_in_scope": True,
            "reasons": ["Probe URL/callback sink with controlled callback host."],
        },
        "open_redirect_probe": {
            "enabled": True,
            "base_score": 2,
            "requires_in_scope": True,
            "reasons": ["Validate redirect target handling across host boundaries."],
        },
        "token_replay_check": {
            "enabled": True,
            "base_score": 2,
            "requires_in_scope": True,
            "reasons": ["Check replayability and scope of leaked/reused tokens."],
        },
        "idor_identifier_probe": {
            "enabled": True,
            "base_score": 2,
            "requires_in_scope": True,
            "reasons": ["Mutate likely object identifiers and compare authorization behavior."],
        },
        "auth_boundary_probe": {
            "enabled": True,
            "base_score": 1,
            "requires_in_scope": True,
            "reasons": ["Compare pre-auth and post-auth behavior transitions."],
        },
        "passive_review": {
            "enabled": True,
            "base_score": 1,
            "requires_in_scope": False,
            "reasons": ["Record evidence and keep this item for manual/passive follow-up."],
        },
    },
}

SSRF_PARAM_HINTS = {"callback", "dest", "destination", "feed", "target", "uri", "url", "webhook"}
REDIRECT_PARAM_HINTS = {"continue", "next", "redirect", "redirect_to", "return", "return_to", "url"}
TOKEN_PARAM_HINTS = {
    "access_token",
    "auth",
    "authorization",
    "bearer",
    "id_token",
    "jwt",
    "refresh_token",
    "session",
    "token",
}
IDOR_PARAM_HINTS = {
    "account_id",
    "customer_id",
    "id",
    "invoice_id",
    "member_id",
    "order_id",
    "profile_id",
    "tenant_id",
    "user",
    "user_id",
}


@dataclass(frozen=True)
class EndpointFacts:
    identifier_presence: bool
    auth_transition: bool
    tenant_marker: bool
    redirect_boundary: bool
    token_presence: bool
    ssrf_sink: bool
    sensitive_data: bool


@dataclass(frozen=True)
class CompoundRule:
    rule_id: str
    requires: tuple[str, ...]
    score_boost: int
    required_sessions: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    steps: tuple[dict[str, object], ...]
    reason: str


COMPOUND_RULES: tuple[CompoundRule, ...] = (
    CompoundRule(
        rule_id="tenant_identifier_access_chain",
        requires=("identifier_presence", "tenant_marker", "auth_transition"),
        score_boost=6,
        required_sessions=("user_a", "user_b"),
        stop_conditions=(
            "stop_on_cross_tenant_data_exposure",
            "stop_on_confirmed_auth_bypass",
        ),
        steps=(
            {
                "action": "token_replay_check",
                "goal": "Capture stable auth token/context for user_a and user_b.",
            },
            {
                "action": "idor_identifier_probe",
                "goal": "Mutate identifier while holding tenant marker constant.",
            },
            {
                "action": "auth_boundary_probe",
                "goal": "Replay mutated identifier across auth boundary/session switch.",
            },
        ),
        reason="Identifier, tenant, and auth-transition facts support a chained cross-tenant access pivot test.",
    ),
    CompoundRule(
        rule_id="redirect_token_replay_chain",
        requires=("redirect_boundary", "token_presence", "auth_transition"),
        score_boost=5,
        required_sessions=("user",),
        stop_conditions=(
            "stop_on_token_replay_acceptance",
            "stop_on_cross_host_redirect_after_auth",
        ),
        steps=(
            {
                "action": "open_redirect_probe",
                "goal": "Establish redirect boundary and external target control.",
            },
            {
                "action": "token_replay_check",
                "goal": "Replay observed token/session across redirected path.",
            },
            {
                "action": "auth_boundary_probe",
                "goal": "Confirm auth state transition is preserved or bypassed.",
            },
        ),
        reason="Redirect + token + auth-transition facts indicate a viable multi-step replay chain.",
    ),
    CompoundRule(
        rule_id="ssrf_internal_reach_chain",
        requires=("ssrf_sink",),
        score_boost=7,
        required_sessions=("user",),
        stop_conditions=(
            "stop_on_internal_host_callback",
            "stop_on_metadata_exposure",
        ),
        steps=(
            {
                "action": "ssrf_callback_probe",
                "goal": "Probe callback sink with internal network targets (localhost, 169.254.169.254).",
            },
            {
                "action": "cloud_metadata_active_probe",
                "goal": "Validate reachability to cloud metadata endpoints via the sink.",
            },
        ),
        reason="SSRF sink indicates a high-confidence path for internal network reachability simulation.",
    ),
    CompoundRule(
        rule_id="ssrf_sensitive_data_chain",
        requires=("ssrf_sink", "sensitive_data"),
        score_boost=8,
        required_sessions=("user",),
        stop_conditions=(
            "stop_on_credential_leak",
            "stop_on_internal_config_exposure",
        ),
        steps=(
            {
                "action": "ssrf_callback_probe",
                "goal": "Pivot SSRF sink to endpoints known to contain sensitive data.",
            },
            {
                "action": "passive_review",
                "goal": "Document exfiltration path from internal sink to sensitive data node.",
            },
        ),
        reason="SSRF sink plus existing sensitive data finding creates a direct simulated exfiltration path.",
    ),
    CompoundRule(
        rule_id="auth_bypass_idor_chain",
        requires=("auth_transition", "identifier_presence"),
        score_boost=6,
        required_sessions=("user_a",),
        stop_conditions=(
            "stop_on_confirmed_auth_bypass",
            "stop_on_idor_exposure",
        ),
        steps=(
            {
                "action": "auth_boundary_probe",
                "goal": "Attempt to bypass authentication at the transition point.",
            },
            {
                "action": "idor_identifier_probe",
                "goal": "Validate if bypassed session allows unauthorized object access.",
            },
        ),
        reason="Auth transition point combined with object identifiers suggests a multi-step bypass/escalation path.",
    ),
    CompoundRule(
        rule_id="auth_bypass_sensitive_data_chain",
        requires=("auth_transition", "sensitive_data"),
        score_boost=7,
        required_sessions=("user_a",),
        stop_conditions=(
            "stop_on_confirmed_auth_bypass",
            "stop_on_sensitive_data_leak",
        ),
        steps=(
            {
                "action": "auth_boundary_probe",
                "goal": "Attempt to bypass authentication at the transition point.",
            },
            {
                "action": "passive_review",
                "goal": "Document exfiltration path from bypassed endpoint to sensitive data node.",
            },
        ),
        reason="Auth transition point combined with sensitive data presence suggests a high-impact bypass path.",
    ),
)


def select_validation_actions(
    *,
    url: str,
    params: list[str] | set[str] | tuple[str, ...] | None,
    signals: list[str] | set[str] | tuple[str, ...] | None,
    scope_hosts: set[str] | None = None,
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    merged = _merge_config(config)
    normalized_params = {str(item).strip().lower() for item in (params or []) if str(item).strip()}
    normalized_signals = {
        str(item).strip().lower() for item in (signals or []) if str(item).strip()
    }
    in_scope = _is_in_scope(url, scope_hosts or set())

    base_ranked = _rank_actions_by_hints(
        merged=merged,
        normalized_params=normalized_params,
        normalized_signals=normalized_signals,
        in_scope=in_scope,
    )

    facts = _build_endpoint_facts(
        normalized_params=normalized_params,
        normalized_signals=normalized_signals,
        url=url,
    )
    plans = _build_compound_validation_plans(
        merged=merged,
        facts=facts,
        in_scope=in_scope,
    )

    if not plans:
        return base_ranked

    fallback_map: dict[str, dict[str, Any]] = {
        str(item.get("action", "")): item for item in base_ranked
    }
    planned_actions: list[dict[str, Any]] = []
    for plan in plans:
        prerequisites: list[str] = [str(a) for a in plan.get("prerequisites", [])]
        score: int = int(plan.get("score", 0))
        for action_name in prerequisites:
            fallback: dict[str, Any] = fallback_map.get(
                action_name, {"action": action_name, "score": 0, "reason": ""}
            )
            planned_actions.append(
                {
                    "action": action_name,
                    "score": max(int(fallback.get("score", 0)), score),
                    "reason": f"{plan.get('reason', '')} Fallback: {fallback.get('reason', '')}".strip(),
                    "plan": {
                        "rule_id": plan.get("rule_id", ""),
                        "required_sessions": plan.get("required_sessions", []),
                        "stop_conditions": plan.get("stop_conditions", []),
                        "steps": plan.get("steps", []),
                    },
                }
            )

    combined: dict[str, dict[str, Any]] = {
        item["action"]: item for item in base_ranked if item.get("action")
    }
    for item in planned_actions:
        existing = combined.get(item["action"])
        if existing is None:
            combined[item["action"]] = item
            continue
        if int(item.get("score", 0)) > int(existing.get("score", 0)):
            combined[item["action"]] = item
            continue
        if "plan" in item and "plan" not in existing:
            merged_reason = f"{existing.get('reason', '')} {item.get('reason', '')}".strip()
            combined[item["action"]] = {
                **existing,
                "plan": item.get("plan"),
                "reason": merged_reason[:320],
            }

    ranked: list[dict[str, Any]] = list(combined.values())
    ranked.sort(key=lambda _item: (-int(_item.get("score", 0)), str(_item.get("action", ""))))
    return ranked


def _rank_actions_by_hints(
    *,
    merged: dict[str, Any],
    normalized_params: set[str],
    normalized_signals: set[str],
    in_scope: bool,
) -> list[dict[str, Any]]:

    scores: dict[str, int] = {}
    reasons: dict[str, list[str]] = {}
    for name, spec in merged["actions"].items():
        if not spec.get("enabled", True):
            continue
        if spec.get("requires_in_scope", True) and not in_scope:
            continue
        scores[name] = int(spec.get("base_score", 0))
        reasons[name] = list(spec.get("reasons", []))

    if normalized_params & SSRF_PARAM_HINTS:
        _bump(
            scores,
            reasons,
            "ssrf_callback_probe",
            3,
            "Parameter name hints SSRF-style sink behavior.",
        )
    if normalized_params & REDIRECT_PARAM_HINTS:
        _bump(
            scores,
            reasons,
            "open_redirect_probe",
            3,
            "Parameter name hints redirect-style control.",
        )
    if normalized_params & TOKEN_PARAM_HINTS:
        _bump(scores, reasons, "token_replay_check", 3, "Parameter name hints token handling.")
    if normalized_params & IDOR_PARAM_HINTS:
        _bump(
            scores,
            reasons,
            "idor_identifier_probe",
            3,
            "Parameter name hints object identifier usage.",
        )

    if any(
        signal.startswith("internal_host_reference") or signal.startswith("dangerous_scheme")
        for signal in normalized_signals
    ):
        _bump(
            scores,
            reasons,
            "ssrf_callback_probe",
            4,
            "Signals include internal-host/dangerous-scheme behavior.",
        )
    if "cross_host_target" in normalized_signals or "scheme_relative_target" in normalized_signals:
        _bump(
            scores,
            reasons,
            "open_redirect_probe",
            4,
            "Signals indicate cross-host redirect potential.",
        )
    if "jwt_like_token" in normalized_signals or "reused_across_urls" in normalized_signals:
        _bump(
            scores,
            reasons,
            "token_replay_check",
            4,
            "Signals indicate token reuse/replay potential.",
        )
    if any("identifier" in signal for signal in normalized_signals):
        _bump(
            scores,
            reasons,
            "idor_identifier_probe",
            4,
            "Signals include identifier-based access pattern.",
        )
    if "auth_flow_endpoint" in normalized_signals or "oauth_redirect_sink" in normalized_signals:
        _bump(
            scores,
            reasons,
            "auth_boundary_probe",
            3,
            "Signals indicate auth-boundary transition flow.",
        )

    ranked: list[dict[str, Any]] = [
        {
            "action": action,
            "score": score,
            "reason": " ".join(dict.fromkeys(reasons[action]))[:320],
        }
        for action, score in scores.items()
    ]
    ranked.sort(key=lambda item: (-int(item["score"]), str(item["action"])))
    return ranked


def _build_endpoint_facts(
    *, normalized_params: set[str], normalized_signals: set[str], url: str
) -> EndpointFacts:
    url_text = str(url).strip().lower()
    identifier_presence = bool(normalized_params & IDOR_PARAM_HINTS) or any(
        "identifier" in value for value in normalized_signals
    )
    auth_transition = bool(
        {
            "auth_flow_endpoint",
            "oauth_redirect_sink",
            "auth_boundary_redirect",
            "auth_boundary",
            "authenticated",
        }
        & normalized_signals
    ) or any(token in url_text for token in ("/login", "/oauth", "/callback", "/session"))
    tenant_marker = bool(
        {"tenant", "tenant_id", "account_id", "organization_id", "org_id"} & normalized_params
    ) or any("tenant" in value or "account" in value for value in normalized_signals)
    redirect_boundary = bool(normalized_params & REDIRECT_PARAM_HINTS) or bool(
        {
            "cross_host_target",
            "scheme_relative_target",
            "redirect",
            "redirect_chain",
            "auth_boundary_redirect",
        }
        & normalized_signals
    )
    token_presence = bool(normalized_params & TOKEN_PARAM_HINTS) or bool(
        {"jwt_like_token", "reused_across_urls", "token"} & normalized_signals
    )
    ssrf_sink = bool(normalized_params & SSRF_PARAM_HINTS) or any(
        value.startswith("internal_host_reference") or value.startswith("dangerous_scheme")
        for value in normalized_signals
    )
    sensitive_data = any(
        hint in normalized_params
        for hint in ("key", "secret", "password", "token", "pii", "ssn", "credit_card")
    ) or any(
        "sensitive" in value or "credential" in value or "secret" in value
        for value in normalized_signals
    )
    return EndpointFacts(
        identifier_presence=identifier_presence,
        auth_transition=auth_transition,
        tenant_marker=tenant_marker,
        redirect_boundary=redirect_boundary,
        token_presence=token_presence,
        ssrf_sink=ssrf_sink,
        sensitive_data=sensitive_data,
    )


def _build_compound_validation_plans(
    *, merged: dict[str, Any], facts: EndpointFacts, in_scope: bool
) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    planner_settings: _PlannerConfig = (
        merged.get("planner", {}) if isinstance(merged.get("planner", {}), dict) else {}
    )
    if not planner_settings.get("planner_enabled", True):
        return plans
    max_plans: int = max(1, int(planner_settings.get("max_plans", 8) or 8))
    fact_map = {
        "identifier_presence": facts.identifier_presence,
        "auth_transition": facts.auth_transition,
        "tenant_marker": facts.tenant_marker,
        "redirect_boundary": facts.redirect_boundary,
        "token_presence": facts.token_presence,
        "ssrf_sink": facts.ssrf_sink,
        "sensitive_data": facts.sensitive_data,
    }
    for rule in COMPOUND_RULES:
        if not in_scope:
            continue
        if not all(bool(fact_map.get(name, False)) for name in rule.requires):
            continue
        enabled_steps = [
            step
            for step in rule.steps
            if merged["actions"].get(str(step.get("action", "")), {}).get("enabled", True)
        ]
        if not enabled_steps:
            continue
        plans.append(
            {
                "rule_id": rule.rule_id,
                "score": int(rule.score_boost),
                "reason": rule.reason,
                "prerequisites": [
                    str(step.get("action", ""))
                    for step in enabled_steps
                    if str(step.get("action", ""))
                ],
                "required_sessions": list(rule.required_sessions),
                "stop_conditions": list(rule.stop_conditions),
                "steps": [
                    {
                        "order": index + 1,
                        "action": str(step.get("action", "")),
                        "goal": str(step.get("goal", "")),
                    }
                    for index, step in enumerate(enabled_steps)
                ],
            }
        )
    plans.sort(key=lambda _item: (-int(_item.get("score", 0)), str(_item.get("rule_id", ""))))
    return plans[:max_plans]


def _merge_config(config: dict[str, Any] | None) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "planner": dict(DEFAULT_SELECTOR_CONFIG.get("planner", {})),
        "actions": {name: dict(spec) for name, spec in DEFAULT_SELECTOR_CONFIG["actions"].items()},
    }
    supplied = config or {}
    supplied_planner = (
        supplied.get("planner", {}) if isinstance(supplied.get("planner", {}), dict) else {}
    )
    if supplied_planner:
        merged["planner"].update(supplied_planner)
    supplied_actions = (
        supplied.get("actions", {}) if isinstance(supplied.get("actions", {}), dict) else {}
    )
    for name, override in supplied_actions.items():
        if name not in merged["actions"]:
            continue
        if isinstance(override, dict):
            merged["actions"][name].update(override)
    return merged


def _is_in_scope(url: str, scope_hosts: set[str]) -> bool:
    matched, _reason = scope_match(url, scope_hosts)
    return matched


def _bump(
    scores: dict[str, int], reasons: dict[str, list[str]], action: str, delta: int, reason: str
) -> None:
    if action not in scores:
        return
    scores[action] += int(delta)
    reasons[action].append(reason)
