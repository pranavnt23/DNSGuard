"""
DNSGuard Detection Module.
Owned by: Member 1 (Threat Detection)

This module handles:
- Multi-signal rule-based DNS tunneling detection
- DGA and suspicious domain lexical analysis
- DNS spoofing and response consistency anomaly detection
- Machine Learning anomaly detection using Isolation Forest
- DNSSEC security evaluation interface
- Multi-detector result aggregation and explainable reporting
- Benchmark evaluation metrics (Precision, Recall, F1, Confusion Matrix)
"""

from detection.rules import (
    DetectionConfig,
    DetectorVerdict,
    RuleEvaluationResult,
    RuleDefinition,
)
from detection.dnssec import (
    DNSSECStatus,
    DNSSECValidationResult,
    evaluate_dnssec,
)
from detection.tunneling import DNSTunnelingDetector
from detection.dga import DGADetector
from detection.spoofing import (
    DNSSpoofingDetector,
    ResponseConsistencyTracker,
    get_consistency_tracker,
)
from detection.anomaly import (
    IsolationForestDetector,
    extract_numeric_feature_vector,
    FEATURE_COLUMNS,
)
from detection.aggregator import (
    DetectionAggregator,
    UnifiedDetectionVerdict,
)
from detection.evaluator import (
    EvaluationReport,
    calculate_binary_metrics,
    evaluate_detector_on_samples,
)
from detection.engine import ThreatDetectionEngine

__version__ = "0.3.0"

__all__ = [
    "ThreatDetectionEngine",
    "DetectionConfig",
    "DetectorVerdict",
    "RuleEvaluationResult",
    "RuleDefinition",
    "DNSSECStatus",
    "DNSSECValidationResult",
    "evaluate_dnssec",
    "DNSTunnelingDetector",
    "DGADetector",
    "DNSSpoofingDetector",
    "ResponseConsistencyTracker",
    "get_consistency_tracker",
    "IsolationForestDetector",
    "extract_numeric_feature_vector",
    "FEATURE_COLUMNS",
    "DetectionAggregator",
    "UnifiedDetectionVerdict",
    "EvaluationReport",
    "calculate_binary_metrics",
    "evaluate_detector_on_samples",
]
