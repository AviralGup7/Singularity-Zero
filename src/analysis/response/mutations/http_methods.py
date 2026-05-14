"""HTTP method override, probing, and flow breaking probes."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url
from src.recon.ranking_support import stage_for_url

from .diff import _variant_diff_summary


def _http_method_probe(
    priority_urls: list[str],
    response_cache: ResponseCache,
    limit: int = 16,
    method: str = "OPTIONS",
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url) or classify_endpoint(url) == "STATIC":
            continue
        ek, ebk = endpoint_signature(url), endpoint_base_key(url)
        resp = response_cache.request(url, method=method, headers={"Cache-Control": "no-cache"})
        if not resp:
            continue
        sc = int(resp.get("status_code") or 0)
        if sc < 200 or sc >= 500:
            continue
        ah = ""
        hdrs = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
        if method.upper() == "OPTIONS":
            ah = hdrs.get("allow", "") or hdrs.get("public", "")
        findings.append(
            {
                "url": url,
                "endpoint_key": ek,
                "endpoint_base_key": ebk,
                "method": method,
                "status_code": sc,
                "allow_header": ah,
                "signals": ["http_method_probe", f"method_{method.lower()}_accepted"],
            }
        )
    findings.sort(key=lambda i: (-i["status_code"], i["url"]))
    return findings[:limit]


def _flow_stage(url: str) -> int | None:
    return stage_for_url(url)


def _redirect_target(response: dict[str, Any]) -> str:
    hdrs = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    return hdrs.get("location", "")


def multi_step_flow_breaking_probe(
    flow_items: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
    max_steps: int = 8,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in flow_items:
        if len(findings) >= limit:
            break
        chain = [str(v).strip() for v in item.get("chain", []) if str(v).strip()]
        if len(chain) < 2:
            continue
        entry_url = chain[0]
        entry_stage: int = _flow_stage(entry_url) or 0
        for si, candidate in enumerate(chain[1 : 1 + max_steps], start=1):
            direct = response_cache.request(
                candidate, headers={"Cache-Control": "no-cache", "Referer": entry_url}
            )
            if not direct:
                continue
            final_url = str(direct.get("final_url") or direct.get("url") or candidate)
            ts: int = _flow_stage(candidate) or si
            fs: int = _flow_stage(final_url) or ts
            ssp = int(direct.get("status_code") or 0) < 400 and fs >= ts
            if not ssp:
                continue
            flow_signals = ["direct_step_access", "flow_break_candidate"]
            flow_evidence: dict[str, Any] = {
                "step_skip_possible": ssp,
                "stage_gap": fs - entry_stage,
            }
            baseline = response_cache.get(entry_url)
            if baseline:
                bb = str(baseline.get("body_text", ""))
                if "csrf" in bb.lower() or "xsrf" in bb.lower():
                    nr = response_cache.request(candidate, headers={"Cache-Control": "no-cache"})
                    if nr:
                        if int(nr.get("status_code") or 0) < 400:
                            flow_signals.append("csrf_not_enforced")
                            flow_evidence["csrf_omission_allowed"] = True
                        else:
                            flow_signals.append("csrf_enforced")
                            flow_evidence["csrf_omission_allowed"] = False
            pc = urlparse(candidate)
            cp = parse_qsl(pc.query, keep_blank_values=True)
            for pn, pv in cp:
                if pn.lower() in {"step", "stage", "state", "phase", "page"} and pv.isdigit():
                    inc = str(int(pv) + 1)
                    tp = [(k, inc if k == pn else v) for k, v in cp]
                    tu = urlunparse(pc._replace(query=urlencode(tp, doseq=True)))
                    t = response_cache.request(tu, headers={"Cache-Control": "no-cache"})
                    if t and int(t.get("status_code") or 0) < 400:
                        flow_signals.append("state_parameter_tampering")
                        flow_evidence["tampered_step"] = inc
                        flow_evidence["tampered_url"] = tu
            findings.append(
                {
                    "url": entry_url,
                    "endpoint_key": endpoint_signature(entry_url),
                    "endpoint_base_key": endpoint_base_key(entry_url),
                    "label": item.get("label", "flow"),
                    "entry_url": entry_url,
                    "skipped_to_url": candidate,
                    "final_url": final_url,
                    "entry_stage": entry_stage,
                    "target_stage": ts,
                    "final_stage": fs,
                    "status_code": direct.get("status_code"),
                    "step_skip_possible": ssp,
                    "signals": sorted(set(flow_signals)),
                    "flow_evidence": flow_evidence,
                }
            )
            break
    findings.sort(key=lambda i: (-i["final_stage"], i["url"]))
    return findings[:limit]


def http_method_override_probe(
    priority_urls: list[str],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    oh = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method-Override", "PUT"),
        ("X-HTTP-Method-Override", "PATCH"),
        ("X-Method-Override", "DELETE"),
        ("X-Original-HTTP-Method", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
        ("X-HTTP-Method-Override", "HEAD"),
        ("X-HTTP-Method-Override", "OPTIONS"),
        ("X-HTTP-Method-Override", "CONNECT"),
        ("X-HTTP-Method-Override", "TRACE"),
        ("X-Method-Override", "PUT"),
        ("X-Method-Override", "PATCH"),
    ]
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url) or classify_endpoint(url) == "STATIC":
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        bs = int(baseline.get("status_code") or 0)
        if bs >= 400 and bs != 405:
            continue
        ek, ebk = endpoint_signature(url), endpoint_base_key(url)
        obs = []
        for hn, hv in oh:
            m = response_cache.request(url, headers={"Cache-Control": "no-cache", hn: hv})
            if not m:
                continue
            ms = int(m.get("status_code") or 0)
            d = _variant_diff_summary(baseline, m)
            mod = (
                d["status_changed"]
                or d["body_similarity"] < 0.9
                or (bs < 400 and ms >= 400 and ms not in (405, 501))
                or (bs == 405 and ms < 400)
            )
            if mod:
                obs.append(
                    {
                        "header": hn,
                        "override_value": hv,
                        "baseline_status": bs,
                        "override_status": ms,
                        "body_similarity": d["body_similarity"],
                        "status_changed": d["status_changed"],
                        "content_changed": d["content_changed"],
                    }
                )
        parsed = urlparse(url)
        rqp = parse_qsl(parsed.query, keep_blank_values=True)
        for mv in ("DELETE", "PUT", "PATCH"):
            tp = [*rqp, ("_method", mv)]
            tu = normalize_url(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))))
            m = response_cache.request(tu, headers={"Cache-Control": "no-cache"})
            if m:
                ms = int(m.get("status_code") or 0)
                d = _variant_diff_summary(baseline, m)
                if d["status_changed"] or d["body_similarity"] < 0.9:
                    obs.append(
                        {
                            "header": "_method_query_param",
                            "override_value": mv,
                            "baseline_status": bs,
                            "override_status": ms,
                            "body_similarity": d["body_similarity"],
                            "status_changed": d["status_changed"],
                            "content_changed": d["content_changed"],
                            "mutated_url": tu,
                        }
                    )
        if obs:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": ek,
                    "endpoint_base_key": ebk,
                    "observations": obs[:6],
                    "method_override_detected": len(obs) >= 2,
                    "signals": sorted(
                        {
                            "http_method_override_probe",
                            "status_divergence" if any(o["status_changed"] for o in obs) else "",
                            "content_divergence" if any(o["content_changed"] for o in obs) else "",
                            "multi_header_consistent" if len(obs) >= 2 else "",
                            "method_param_injection"
                            if any(o.get("header") == "_method_query_param" for o in obs)
                            else "",
                            "auth_bypass_via_method"
                            if any(
                                o["baseline_status"] < 400
                                and o["override_status"] < 400
                                and o["override_status"] != bs
                                for o in obs
                            )
                            else "",
                        }
                        - {""}
                    ),
                }
            )
    findings.sort(
        key=lambda i: (not i["method_override_detected"], -len(i["observations"]), i["url"])
    )
    return findings[:limit]
