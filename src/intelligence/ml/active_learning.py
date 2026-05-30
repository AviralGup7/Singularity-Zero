"""Continuous Active Learning controller for findings triage."""

from __future__ import annotations

import logging
import time
from typing import Any

from src.intelligence.ml.registry import ModelVersion, ModelVersionRegistry
from src.intelligence.ml.xgboost_pipeline import XGBoostSeverityPipeline

logger = logging.getLogger(__name__)


class ActiveLearningController:
    """Manages training cycles, validation partitions, and registry activation."""

    def __init__(self, registry: ModelVersionRegistry) -> None:
        self.registry = registry
        self.pipeline = XGBoostSeverityPipeline()

    def retrain_from_telemetry(self, db_path: str, run_id: str) -> dict[str, Any]:
        """Extract labeled finding outcomes from the SQLite database and fit a new pipeline version."""
        import sqlite3

        findings: list[dict[str, Any]] = []
        labels: list[float] = []

        try:
            with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row

                # 1. Fetch triaged feedback events
                try:
                    raw_rows = conn.execute(
                        "SELECT * FROM feedback_events ORDER BY timestamp DESC LIMIT 3000"
                    ).fetchall()

                    # Poisoning defense: Group FPs to verify confirmation threshold (N>=3)
                    fp_counts: dict[tuple[Any, Any], int] = {}
                    for row in raw_rows:
                        item = dict(row)
                        if bool(item.get("was_false_positive")):
                            key = (item.get("finding_category"), item.get("plugin_name"))
                            fp_counts[key] = fp_counts.get(key, 0) + 1

                    # Poisoning defense: Detect anomalous bursts of FP feedback to quarantine poisoning attempts
                    fp_timeframes: dict[str, list[float]] = {}  # run_id -> list of timestamps
                    anomalous_runs = set()
                    for row in raw_rows:
                        item = dict(row)
                        if bool(item.get("was_false_positive")):
                            rid = item.get("run_id") or "unknown"
                            ts_str = item.get("timestamp") or ""
                            try:
                                # Try parsing numeric or ISO format timestamps
                                if isinstance(ts_str, (int, float)):
                                    ts = float(ts_str)
                                else:
                                    import datetime

                                    ts = datetime.datetime.fromisoformat(str(ts_str)).timestamp()
                            except Exception:
                                ts = time.time()
                            fp_timeframes.setdefault(rid, []).append(ts)

                    for rid, ts_list in fp_timeframes.items():
                        if len(ts_list) >= 5:
                            ts_list = sorted(ts_list)
                            # Check if 5 or more FPs were submitted within 60 seconds
                            for i in range(len(ts_list) - 4):
                                if ts_list[i + 4] - ts_list[i] <= 60:
                                    anomalous_runs.add(rid)
                                    logger.warning(
                                        "Poisoning protection: Detected FP submission burst in run %s (quarantined).",
                                        rid,
                                    )
                                    break

                    for row in raw_rows:
                        item = dict(row)
                        was_tp = bool(item.get("was_validated")) and not bool(
                            item.get("was_false_positive")
                        )
                        was_fp = bool(item.get("was_false_positive"))
                        if not was_tp and not was_fp:
                            continue

                        # Apply Poisoning Protection Policies
                        if was_fp:
                            # Defense 1: Minimum confirmation threshold
                            key = (item.get("finding_category"), item.get("plugin_name"))
                            if fp_counts.get(key, 0) < 3:
                                logger.info(
                                    "Poisoning protection: Omitted FP feedback for %s due to low confirmation threshold (%d/3).",
                                    key,
                                    fp_counts.get(key, 0),
                                )
                                continue

                            # Defense 2: Quarantine anomalous runs/bursts
                            rid = item.get("run_id") or "unknown"
                            if rid in anomalous_runs:
                                logger.info(
                                    "Poisoning protection: Quarantining feedback from run %s due to anomalous submission burst.",
                                    rid,
                                )
                                continue

                        finding = {
                            "category": item.get("finding_category"),
                            "severity": item.get("finding_severity"),
                            "confidence": item.get("finding_confidence"),
                            "decision": item.get("finding_decision"),
                            "plugin_name": item.get("plugin_name"),
                            "parameter_name": item.get("parameter_name"),
                            "parameter_type": item.get("parameter_type"),
                            "endpoint_type": item.get("endpoint_type"),
                            "url": item.get("target_endpoint"),
                            "host": item.get("target_host"),
                            "response_delta_score": item.get("response_delta_score"),
                        }
                        findings.append(finding)
                        labels.append(1.0 if was_tp else 0.0)
                except sqlite3.Error as e:
                    logger.debug("ActiveLearning: feedback_events table read skipped: %s", e)

                # 2. Fetch validated findings
                try:
                    rows = conn.execute(
                        """SELECT * FROM findings
                           WHERE lifecycle_state IN ('VALIDATED', 'EXPLOITABLE', 'REPORTABLE')
                              OR decision = 'DROP'
                           ORDER BY created_at DESC LIMIT 2000"""
                    ).fetchall()
                    for row in rows:
                        item = dict(row)
                        lifecycle = str(item.get("lifecycle_state") or "").lower()
                        decision = str(item.get("decision") or "").lower()

                        label = (
                            1.0 if lifecycle in {"validated", "exploitable", "reportable"} else 0.0
                        )
                        if decision == "drop":
                            label = 0.0

                        # Safely parse JSON evidence
                        import json

                        evidence = item.get("evidence")
                        if isinstance(evidence, str) and evidence:
                            try:
                                item["evidence"] = json.loads(evidence)
                            except ValueError:
                                item["evidence"] = {}
                        elif not isinstance(evidence, dict):
                            item["evidence"] = {}

                        findings.append(item)
                        labels.append(label)
                except sqlite3.Error as e:
                    logger.debug("ActiveLearning: findings table read skipped: %s", e)

        except Exception as e:
            logger.error("ActiveLearning: Database extraction failed: %s", e)
            return {"status": "failed", "reason": "db_error"}

        if len(findings) < 15:
            logger.info(
                "ActiveLearning: Insufficient labeled samples (%d/15) to train a new model version.",
                len(findings),
            )
            return {"status": "insufficient_data", "samples": len(findings)}

        # Fit model pipeline
        new_pipeline = XGBoostSeverityPipeline()
        success = new_pipeline.fit(findings, labels)
        if not success:
            return {"status": "failed", "reason": "fit_error"}

        # Validate accuracy on training partition
        predictions = [new_pipeline.predict_probability(f) for f in findings]
        correct = sum(
            1
            for p, y in zip(predictions, labels)
            if (p >= 0.5 and y >= 0.5) or (p < 0.5 and y < 0.5)
        )
        accuracy = correct / len(findings)

        # Register new version
        new_version = f"severity-xgboost-v{int(time.time())}"
        model_meta = {
            "accuracy": round(accuracy, 4),
            "samples": len(findings),
            "retrained_at": time.time(),
        }

        mv = ModelVersion(
            name="severity_model",
            version=new_version,
            metadata=model_meta,
        )

        self.registry.register(mv, activate=True, pipeline=new_pipeline)
        self.pipeline = new_pipeline

        logger.info(
            "ActiveLearning: Successfully registered and activated new ML severity model version %s (Accuracy: %.2f%%)",
            new_version,
            accuracy * 100.0,
        )

        return {
            "status": "success",
            "activated_version": new_version,
            "samples": len(findings),
            "accuracy": accuracy,
        }
