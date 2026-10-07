"""
Evaluation Metrics & Benchmark Validation Module for DNSGuard.

Computes precision, recall, F1-score, accuracy, and confusion matrix metrics
against labeled benchmark test sets.
Transparently labels results as laboratory demonstration evaluations.
"""

from typing import Any, Dict, List, Tuple
from pydantic import BaseModel, Field, ConfigDict


class EvaluationReport(BaseModel):
    """Structured performance report for viva review and academic audit."""
    dataset_name: str
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]] = Field(description="[[TN, FP], [FN, TP]]")
    per_threat_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    is_synthetic_benchmark: bool = True
    disclaimer: str = (
        "Evaluation conducted on controlled synthetic demonstration data. "
        "Metrics reflect rule/model behavioral alignment and are not claims of production efficacy."
    )

    model_config = ConfigDict(from_attributes=True)


def calculate_binary_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    """
    Computes standard binary classification metrics.

    Args:
        y_true: Binary ground truth list (1=suspicious/threat, 0=benign).
        y_pred: Binary predicted labels list (1=detected, 0=clean).

    Returns:
        Dict containing accuracy, precision, recall, f1, and confusion matrix.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"Length mismatch: y_true ({len(y_true)}) != y_pred ({len(y_pred)})")

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    accuracy = round((tp + tn) / max(total, 1), 4)
    precision = round(tp / max(tp + fp, 1), 4)
    recall = round(tp / max(tp + fn, 1), 4)

    if (precision + recall) > 0:
        f1 = round(2.0 * (precision * recall) / (precision + recall), 4)
    else:
        f1 = 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def evaluate_detector_on_samples(
    engine: Any,
    labeled_samples: List[Dict[str, Any]],
    dataset_name: str = "Synthetic Lab Benchmark v1",
) -> EvaluationReport:
    """
    Runs the detection engine over labeled samples and generates an EvaluationReport.

    Args:
        engine: ThreatDetectionEngine instance.
        labeled_samples: List of dictionaries with domain, features, and 'is_threat' or 'synthetic_label'.
        dataset_name: Identifier for the benchmark dataset.

    Returns:
        EvaluationReport: Complete evaluation metrics.
    """
    y_true = []
    y_pred = []
    breakdown: Dict[str, Dict[str, int]] = {
        "DGA": {"total": 0, "detected": 0},
        "TUNNELING": {"total": 0, "detected": 0},
        "SPOOFING": {"total": 0, "detected": 0},
        "BENIGN": {"total": 0, "clean": 0, "false_positive": 0},
    }

    for item in labeled_samples:
        label_str = str(item.get("synthetic_label", "")).lower()
        is_threat = bool(item.get("is_threat", False) or "synthetic_" in label_str)
        y_true.append(1 if is_threat else 0)

        # Run engine evaluation
        domain = item.get("domain") or item.get("queried_domain") or ""
        verdict = engine.analyze_feature_dict(item)
        pred_threat = 1 if verdict.is_suspicious else 0
        y_pred.append(pred_threat)

        # Track per-category breakdown
        if "dga" in label_str:
            breakdown["DGA"]["total"] += 1
            if verdict.is_suspicious and verdict.primary_threat_type.value == "DGA":
                breakdown["DGA"]["detected"] += 1
        elif "tunneling" in label_str:
            breakdown["TUNNELING"]["total"] += 1
            if verdict.is_suspicious and verdict.primary_threat_type.value == "TUNNELING":
                breakdown["TUNNELING"]["detected"] += 1
        elif "spoofing" in label_str:
            breakdown["SPOOFING"]["total"] += 1
            if verdict.is_suspicious and verdict.primary_threat_type.value == "SPOOFING":
                breakdown["SPOOFING"]["detected"] += 1
        else:
            breakdown["BENIGN"]["total"] += 1
            if not verdict.is_suspicious:
                breakdown["BENIGN"]["clean"] += 1
            else:
                breakdown["BENIGN"]["false_positive"] += 1

    metrics = calculate_binary_metrics(y_true, y_pred)

    return EvaluationReport(
        dataset_name=dataset_name,
        total_samples=len(labeled_samples),
        true_positives=metrics["tp"],
        false_positives=metrics["fp"],
        true_negatives=metrics["tn"],
        false_negatives=metrics["fn"],
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
        confusion_matrix=metrics["confusion_matrix"],
        per_threat_breakdown=breakdown,
        is_synthetic_benchmark=True,
    )
