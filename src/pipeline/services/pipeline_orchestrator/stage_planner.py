"""StagePlanner and BudgetAllocator for adaptive pipeline stage insertion and resource allocation."""

from __future__ import annotations

import logging
from typing import Any

from src.core.models.stage_result import StageStatus
from src.infrastructure.resource_guard import ResourceGuard

logger = logging.getLogger(__name__)

class StagePlanner:
    def __init__(self, config: Any, ctx: Any, learning_integration: Any) -> None:
        self.config = config
        self.ctx = ctx
        self.learning_integration = learning_integration
        self.resource_guard = ResourceGuard()

    def plan_stages(self, remaining_stages: list[str]) -> tuple[list[str], dict[str, Any]]:
        adjusted_stages = list(remaining_stages)
        resources: dict[str, Any] = {}
        result = self.ctx.result if hasattr(self.ctx, "result") else self.ctx
        urls = getattr(result, "urls", []) or []
        scope_entries = getattr(result, "scope_entries", []) or []

        try:
            self.resource_guard.check_critical_oom()
        except RuntimeError as exc:
            logger.error("StagePlanner: critical OOM detected: %s", exc)
            if hasattr(result, "stage_status"):
                result.stage_status["pipeline"] = StageStatus.FAILED.value
            if hasattr(result, "module_metrics"):
                result.module_metrics["pipeline"] = {
                    "status": "error",
                    "error": str(exc),
                    "failure_reason": str(exc),
                    "fatal": True,
                }
            raise

        target_count = len(scope_entries)
        url_count = len(urls)
        findings_count = len(getattr(result, "reportable_findings", []) or [])
        stage_order_map = {name: idx for idx, name in enumerate(remaining_stages)}

        if findings_count >= 50 and "threat_modeling" not in adjusted_stages and "threat_modeling" not in getattr(result, "stage_status", {}):
            if "reporting" in adjusted_stages:
                rep_idx = adjusted_stages.index("reporting")
                adjusted_stages.insert(rep_idx, "threat_modeling")
            else:
                adjusted_stages.append("threat_modeling")
            logger.info("StagePlanner: Findings count (%d) >= 50. Auto-injected threat_modeling enrichment.", findings_count)
            resources["expand_report_details"] = True

        active_stages = [s for s in adjusted_stages if s not in ("ranker", "deserialize_scope")]
        filtered_stages: list[str] = []
        for s in active_stages:
            skip, reason = self.resource_guard.should_skip_stage(s, target_count, url_count)
            if skip:
                logger.info("StagePlanner: Skipping stage '%s' due to resource guard: %s", s, reason)
                if hasattr(result, "stage_status"):
                    result.stage_status[s] = StageStatus.SKIPPED.value
                if hasattr(result, "module_metrics"):
                    result.module_metrics[s] = {
                        "status": "skipped",
                        "reason": reason or "insufficient_ram",
                    }
                continue
            filtered_stages.append(s)
        adjusted_stages = filtered_stages

        has_js = any(str(u).endswith(".js") or ".js?" in str(u) for u in urls)
        if has_js and "semgrep" not in adjusted_stages and "semgrep" not in getattr(result, "stage_status", {}):
            adjusted_stages.append("semgrep")
            logger.info("StagePlanner: Auto-inserted 'semgrep' stage due to discoverable Javascript URLs.")

        has_wildcard = any("*" in str(entry) for entry in scope_entries)
        subdomains = getattr(result, "subdomains", []) or []
        if has_wildcard and len(subdomains) > 0 and "subdomain_takeover" not in adjusted_stages and "subdomain_takeover" not in getattr(result, "stage_status", {}):
            adjusted_stages.append("subdomain_takeover")
            logger.info("StagePlanner: Auto-inserted 'subdomain_takeover' stage due to wildcards and enumerated subdomains.")

        time_budget = getattr(self.config, "estimated_time_budget", 3600)

        if url_count > 0:
            default_concurrency = int(getattr(self.config, "default_concurrency", 10))
            base_concurrency = default_concurrency
            depth = 2
            stage_depth_map = {10: 2, 80: 3, 150: 5}
            for threshold, d in sorted(stage_depth_map.items(), reverse=True):
                if url_count >= threshold:
                    base_concurrency = threshold
                    depth = d
                    break
            cap = self.resource_guard.get_concurrency_cap("active_scan", base_concurrency)
            cap = self.resource_guard.get_concurrency_cap("urls", cap)
            resources["httpx_concurrency"] = min(cap, base_concurrency)
            resources["katana_depth"] = depth
            resources["rate_limit_delay"] = 0.5 if url_count >= 50000 else (0.1 if url_count >= 5000 else 0.0)
            logger.info("StagePlanner: Calibrated resources for %d URLs: concurrency=%d, depth=%d", url_count, resources["httpx_concurrency"], resources["katana_depth"])

        live_hosts = getattr(result, "live_hosts", []) or []
        if len(live_hosts) > 3 and "waf" in adjusted_stages:
            sample_size = max(3, int(len(live_hosts) * 0.05))
            waf_detected_count = self._sample_waf_detection(list(live_hosts)[:sample_size])
            if waf_detected_count == 0:
                logger.info("StagePlanner: WAF sample-check of %d hosts showed 0 detections. Skipping remaining waf checks.", sample_size)
                adjusted_stages.remove("waf")
                if hasattr(result, "stage_status"):
                    result.stage_status["waf"] = StageStatus.SKIPPED.value
                    result.module_metrics["waf"] = {"status": "skipped", "reason": "probabilistic_skip_low_confidence"}

        final_stages: list[str] = []
        total_value = 0.0
        stage_values: dict[str, float] = {}
        for s in adjusted_stages:
            val = self.learning_integration.predict_stage_value(s, self.ctx)
            stage_values[s] = val
            total_value += val

        remaining_time = time_budget
        threshold = 0.3
        adjusted_order_map = {name: idx for idx, name in enumerate(adjusted_stages)}
        ordered_stages = sorted(stage_values.items(), key=lambda kv: adjusted_order_map.get(kv[0], 99))

        for s, val in ordered_stages:
            if val < threshold:
                logger.info("StagePlanner: Skipping stage '%s' (predicted marginal value %.2f < threshold %.2f)", s, val, threshold)
                if hasattr(result, "stage_status"):
                    result.stage_status[s] = StageStatus.SKIPPED.value
                if hasattr(result, "module_metrics"):
                    result.module_metrics[s] = {"status": "skipped", "reason": f"low_marginal_value_{val:.2f}"}
                continue

            allocated_time = int((val / max(0.1, total_value)) * remaining_time)
            resources[f"{s}_stage_timeout_seconds"] = max(60, allocated_time)
            final_stages.append(s)

        return final_stages, resources

    def _sample_waf_detection(self, sample_urls: list[str]) -> int:
        headers_list = [({"host": url.split("/")[2]} if len(url.split("/")) > 2 else {}) for url in sample_urls]
        detection_count = 0
        try:
            from src.detection.waf import fingerprint_response
        except ImportError:
            logger.debug("StagePlanner: WAF detector import unavailable; assuming 0 detections from sample.")
            return 0
        for headers in headers_list:
            match = fingerprint_response(headers)
            if match.confidence > 0.25:
                detection_count += 1
        return detection_count
