from typing import Any

from src.analysis.helpers import classify_endpoint

MANUAL_QUEUE_CATEGORIES = {
    "idor",
    "ssrf",
    "oauth_flow",
    "open_redirect",
    "token_leak",
    "sensitive_data",
    "anomaly",
    "behavioral_deviation",
    "payment",
    "access_control",
    "session",
    "business_logic",
    "redirect",
    "server_side_injection",
    "ai_surface",
}


def derive_endpoint_type(item: dict[str, Any]) -> str:
    return str(
        item.get("endpoint_type")
        or item.get("evidence", {}).get("endpoint_type")
        or classify_endpoint(str(item.get("url", "")))
    ).upper()


def build_review_brief(
    item: dict[str, Any],
    replay_id: str,
    request_context: dict[str, Any],
    proof_bundle: dict[str, Any],
    chain_simulation: dict[str, Any],
) -> str:
    return (
        f"Title: {item.get('title', 'Review finding')}\n"
        f"URL: {item.get('url', '')}\n"
        f"Severity: {item.get('severity', 'info')}\n"
        f"Confidence: {round(float(item.get('confidence', 0)) * 100)}%\n"
        f"History: {item.get('history_status', 'new')}\n"
        f"Combined signal: {item.get('combined_signal', 'none')}\n"
        f"Replay id: {replay_id or 'n/a'}\n"
        f"Variant: {request_context.get('parameter', '')}={request_context.get('variant', '')}\n"
        f"Suggested review: {item.get('next_step', '')}\n"
        f"Auth replay modes: {', '.join(mode.get('name', '') for mode in proof_bundle.get('auth_replay_modes', [])) or 'none'}\n"
        f"Chain simulation: {chain_simulation.get('summary', 'n/a')}\n"
        f"Curl PoC:\n{proof_bundle.get('curl', '')}\n"
        f"Python PoC:\n{proof_bundle.get('python', '')}\n"
    )


def build_automation_tasks(
    *,
    replay_id: str,
    proof_bundle: dict[str, Any],
    endpoint_type: str,
    is_api_replay_candidate: bool,
) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    if is_api_replay_candidate and replay_id:
        tasks.append(
            {
                "kind": "replay_variant_inherit",
                "title": "Replay Variant (Inherited Auth)",
                "url": "",
            }
        )
        tasks.append(
            {"kind": "replay_variant_anonymous", "title": "Replay Variant (Anonymous)", "url": ""}
        )
    if proof_bundle.get("curl"):
        tasks.append(
            {
                "kind": "run_curl_poc",
                "title": "Run curl PoC",
                "command": proof_bundle.get("curl", ""),
            }
        )
    if proof_bundle.get("python"):
        tasks.append(
            {
                "kind": "run_python_poc",
                "title": "Run Python PoC",
                "command": proof_bundle.get("python", ""),
            }
        )
    if endpoint_type == "API" and not tasks:
        tasks.append(
            {"kind": "collect_api_baseline", "title": "Collect API baseline and compare statuses"}
        )
    return tasks


def attach_queue_replay_links(
    queue: list[dict[str, Any]], *, target_name: str, run_name: str
) -> None:
    for item in queue:
        replay_id = str(item.get("replay_id", "")).strip()
        if not replay_id:
            continue
        item["replay_url"] = (
            f"/api/replay?target={target_name}&run={run_name}&replay_id={replay_id}"
        )
        item["anonymous_replay_url"] = (
            f"/api/replay?target={target_name}&run={run_name}&replay_id={replay_id}&auth_mode=anonymous"
        )
        for task in item.get("automation_tasks", []):
            if task.get("kind") == "replay_variant_inherit":
                task["url"] = item["replay_url"]
            elif task.get("kind") == "replay_variant_anonymous":
                task["url"] = item["anonymous_replay_url"]
