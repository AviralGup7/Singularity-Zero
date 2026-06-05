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

                    # Poisoning defense: Group FPs to verify confirmation threshold (N>=3).
                    # The first pass must *exclude* rows from runs that were later flagged as
                    # anomalous, otherwise the per-key counter is inflated by the very
                    # poisoning bursts we are trying to detect, and legitimate FP confirmations
                    # would be over-counted.
                    anomalous_runs_ts: dict[str, list[float]] = {}
                    for row in raw_rows:
                        item = dict(row)
                        if bool(item.get("was_false_positive")):
                            rid = item.get("run_id") or "unknown"
                            ts_str = item.get("timestamp") or ""
                            try:
                                if isinstance(ts_str, (int, float)):
                                    ts = float(ts_str)
                                else:
                                    import datetime

                                    ts = datetime.datetime.fromisoformat(str(ts_str)).timestamp()
                            except Exception:
                                ts = time.time()
                            anomalous_runs_ts.setdefault(rid, []).append(ts)
                    # Compute anomalous_runs *first* by checking burst windows, then
                    # rebuild the FP counter excluding those quarantined runs.
                    confirmed_anomalous: set[str] = set()
                    for rid, ts_list in anomalous_runs_ts.items():
                        if not isinstance(ts_list, list):
                            continue
                        if len(ts_list) < 5:
                            continue
                        ts_list = sorted(ts_list)
                        for i in range(len(ts_list) - 4):
                            if ts_list[i + 4] - ts_list[i] <= 60:
                                confirmed_anomalous.add(rid)
                                logger.warning(
                                    "Poisoning protection: Detected FP submission burst in run %s (quarantined).",
                                    rid,
                                )
                                break

                    fp_counts: dict[tuple[Any, Any], int] = {}
                    for row in raw_rows:
                        item = dict(row)
                        if not bool(item.get("was_false_positive")):
                            continue
                        rid = item.get("run_id") or "unknown"
                        if rid in confirmed_anomalous:
                            # Exclude FP confirmations that came from a quarantined burst run -
                            # they are exactly the kind of poisoned input we don't trust.
                            continue
                        key = (item.get("finding_category"), item.get("plugin_name"))
                        fp_counts[key] = fp_counts.get(key, 0) + 1

                    fp_timeframes: dict[str, list[float]] = {}  # run_id -> list of timestamps
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
                                    logger.debug(
                                        "Anomalous burst already recorded for run %s",
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
                            if rid in confirmed_anomalous:
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

        # Hold out a stratified validation partition so the reported accuracy is
        # measured on samples the model has never seen. Without this split the
        # metric would be training-set accuracy, which always approaches 1.0
        # for tree-based models and gives a false sense of model quality.
        import random

        indices = list(range(len(findings)))
        random.seed(42)
        random.shuffle(indices)
        # Use a fixed 80/20 split for reproducibility. Falling back to a small
        # validation set when samples are scarce is acceptable here because the
        # primary signal of "fit succeeded" is still the holdout accuracy.
        val_count = max(1, len(findings) // 5)
        val_indices = set(indices[:val_count])
        train_findings = [findings[i] for i in indices if i not in val_indices]
        train_labels = [labels[i] for i in indices if i not in val_indices]
        val_findings = [findings[i] for i in indices if i in val_indices]
        val_labels = [labels[i] for i in indices if i in val_indices]

        # Fit model pipeline
        new_pipeline = XGBoostSeverityPipeline()
        success = new_pipeline.fit(train_findings, train_labels)
        if not success:
            return {"status": "failed", "reason": "fit_error"}

        # Validate accuracy on the held-out partition (not on training data).
        predictions = [new_pipeline.predict_probability(f) for f in val_findings]
        correct = sum(
            1
            for p, y in zip(predictions, val_labels)
            if (p >= 0.5 and y >= 0.5) or (p < 0.5 and y < 0.5)
        )
        accuracy = correct / max(len(val_findings), 1)

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
