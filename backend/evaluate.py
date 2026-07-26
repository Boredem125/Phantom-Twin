"""
evaluate.py — Precision/recall/AUC evaluation for PHANTOM TWIN.

Runs the detection pipeline on test.csv, compares against labels_test.csv,
prints per-class precision/recall/F1, overall AUC-ROC, and confusion matrix.

Usage:
    python backend/evaluate.py \
        --test backend/data/test.csv \
        --labels backend/data/labels_test.csv
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models.profiler import load_profile
from backend.models.detector import score_event, load_model
from backend.models.classifier import classify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("evaluate")

ALL_LABELS = [
    "normal",
    "brute_force",
    "impossible_travel",
    "credential_stuffing",
    "lateral_movement",
    "device_spoofing",
    "low_and_slow",
    "insider_drift",
]


def run_evaluation(test_csv: str, labels_csv: str) -> None:
    """Run full evaluation pipeline and print metrics."""
    logger.info("Loading test data from %s…", test_csv)
    df_test = pd.read_csv(test_csv)
    df_labels = pd.read_csv(labels_csv)

    # Align labels
    df_merged = df_test.merge(
        df_labels[["entity_id", "timestamp", "label"]],
        on=["entity_id", "timestamp"],
        how="left",
    )
    df_merged["label"] = df_merged["label"].fillna("normal")

    logger.info("Loaded %d test events. Label distribution:", len(df_merged))
    for lbl, cnt in df_merged["label"].value_counts().items():
        logger.info("  %-25s %d (%.2f%%)", lbl, cnt, cnt / len(df_merged) * 100)

    # Load model (optional — evaluates even without it)
    model = None
    model_path = "backend/models/iso_forest.pkl"
    if os.path.exists(model_path):
        try:
            model = load_model()
            logger.info("Isolation Forest loaded for evaluation.")
        except Exception as exc:
            logger.warning("Could not load model: %s", exc)
    else:
        logger.warning("Model not found — scoring without Isolation Forest.")

    y_true: list[str] = []
    y_pred: list[str] = []
    risk_scores: list[float] = []
    is_anomaly_true: list[int] = []
    is_anomaly_pred_score: list[float] = []

    # Simple rolling context windows for classification
    from collections import deque
    entity_recent: dict[str, deque] = {}
    global_recent: deque = deque(maxlen=1000)

    total = len(df_merged)
    for i, (_, row) in enumerate(df_merged.iterrows()):
        if i % 500 == 0:
            logger.info("  Processing event %d/%d…", i, total)

        event = row.to_dict()
        true_label = str(event.pop("label", "normal"))

        entity_id = str(event.get("entity_id", ""))
        entity_type = str(event.get("entity_type", "user"))

        if entity_id not in entity_recent:
            entity_recent[entity_id] = deque(maxlen=500)

        profile = load_profile(entity_id, entity_type)
        score_result = score_event(event, profile, model)
        risk_score = score_result["risk_score"]
        deviations = score_result["feature_deviations"]

        entity_recent[entity_id].append(event)
        global_recent.append(event)

        recent = list(entity_recent[entity_id])
        recent_all = list(global_recent)

        attack_type, confidence, _ = classify(
            event=event,
            deviations=deviations,
            recent_events=recent,
            recent_all_events=recent_all,
            profile=profile,
            risk_score=risk_score,
        )

        y_true.append(true_label)
        y_pred.append(attack_type)
        risk_scores.append(risk_score)
        is_anomaly_true.append(0 if true_label == "normal" else 1)
        is_anomaly_pred_score.append(risk_score / 100.0)

    # ── Print results ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PHANTOM TWIN — Evaluation Results")
    print("=" * 70)

    present_labels = sorted(set(y_true) | set(y_pred))
    print("\nPer-class Precision / Recall / F1:")
    print(classification_report(y_true, y_pred, labels=present_labels, zero_division=0))

    # Confusion matrix
    print("Confusion Matrix:")
    cm = confusion_matrix(y_true, y_pred, labels=present_labels)
    cm_df = pd.DataFrame(cm, index=present_labels, columns=present_labels)
    print(cm_df.to_string())

    # AUC-ROC (binary: normal vs anomaly)
    if len(set(is_anomaly_true)) > 1:
        auc = roc_auc_score(is_anomaly_true, is_anomaly_pred_score)
        print(f"\nBinary AUC-ROC (normal vs anomaly): {auc:.4f}")
    else:
        print("\nAUC-ROC: skipped (only one class present in labels).")

    # FPR at top 1% threshold
    threshold_idx = max(1, int(len(risk_scores) * 0.01))
    sorted_scores = sorted(zip(risk_scores, is_anomaly_true), key=lambda x: -x[0])
    top1pct = sorted_scores[:threshold_idx]
    tp = sum(1 for _, lbl in top1pct if lbl == 1)
    fp = sum(1 for _, lbl in top1pct if lbl == 0)
    total_neg = sum(1 for lbl in is_anomaly_true if lbl == 0)
    fpr_top1 = fp / max(total_neg, 1)
    precision_top1 = tp / max(len(top1pct), 1)

    print(f"\nAt top-1% score threshold ({threshold_idx} events):")
    print(f"  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  FPR:             {fpr_top1:.4f} ({fpr_top1 * 100:.2f}%)")
    print(f"  Precision:       {precision_top1:.4f} ({precision_top1 * 100:.2f}%)")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHANTOM TWIN — Evaluator")
    parser.add_argument("--test", type=str, default="backend/data/test.csv")
    parser.add_argument("--labels", type=str, default="backend/data/labels_test.csv")
    args = parser.parse_args()

    if not os.path.exists(args.test):
        logger.error("Test file not found: %s", args.test)
        sys.exit(1)
    if not os.path.exists(args.labels):
        logger.error("Labels file not found: %s", args.labels)
        sys.exit(1)

    run_evaluation(args.test, args.labels)
