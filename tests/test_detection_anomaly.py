"""
Unit tests for Machine Learning Anomaly Detection (Isolation Forest) in DNSGuard.
"""

import os
import tempfile
import pytest
from database.models import DetectionType
from detection.anomaly import (
    IsolationForestDetector,
    extract_numeric_feature_vector,
    FEATURE_COLUMNS,
)


def test_numeric_feature_vector_extraction():
    """Verify that extraction produces 10-dimensional numeric vector without nulls."""
    features = {
        "domain_length": 15,
        "subdomain_count": 2,
        "entropy": 3.45,
        "vowel_ratio": 0.35,
        "digit_ratio": 0.10,
        "max_consonant_sequence": 3,
        "query_type_code": 1,
        "ttl": 300,
        "packet_size": 75,
        "query_rate_per_sec": 1.2,
    }

    vec = extract_numeric_feature_vector(features)
    assert len(vec) == 10
    assert len(vec) == len(FEATURE_COLUMNS)
    assert all(isinstance(x, (int, float)) for x in vec)


def test_isolation_forest_fit_and_predict():
    """Verify training, inference, and score normalization."""
    detector = IsolationForestDetector()

    # Train on small benign sample collection
    benign_samples = [
        {"domain_length": 10, "subdomain_count": 0, "entropy": 2.5, "vowel_ratio": 0.5, "digit_ratio": 0.0, "max_consonant_sequence": 2, "query_type_code": 1, "ttl": 300, "packet_size": 64, "query_rate_per_sec": 0.1},
        {"domain_length": 12, "subdomain_count": 1, "entropy": 2.8, "vowel_ratio": 0.45, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 70, "query_rate_per_sec": 0.2},
        {"domain_length": 14, "subdomain_count": 1, "entropy": 2.9, "vowel_ratio": 0.40, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 72, "query_rate_per_sec": 0.1},
        {"domain_length": 11, "subdomain_count": 0, "entropy": 2.6, "vowel_ratio": 0.45, "digit_ratio": 0.0, "max_consonant_sequence": 2, "query_type_code": 1, "ttl": 300, "packet_size": 68, "query_rate_per_sec": 0.1},
        {"domain_length": 13, "subdomain_count": 1, "entropy": 2.7, "vowel_ratio": 0.42, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 69, "query_rate_per_sec": 0.1},
        {"domain_length": 15, "subdomain_count": 1, "entropy": 3.0, "vowel_ratio": 0.38, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 75, "query_rate_per_sec": 0.2},
    ]

    fit_summary = detector.fit(benign_samples, contamination=0.10)
    assert detector.is_trained is True
    assert fit_summary["sample_count"] == 6

    # Normal inlier prediction
    normal_verdict = detector.evaluate(benign_samples[0])
    assert normal_verdict.threat_type == DetectionType.ANOMALY_ML
    assert normal_verdict.score < 50.0  # Normal traffic has low anomaly score

    # Extreme outlier prediction
    extreme_outlier = {
        "domain_length": 120,
        "subdomain_count": 10,
        "entropy": 4.95,
        "vowel_ratio": 0.05,
        "digit_ratio": 0.60,
        "max_consonant_sequence": 15,
        "query_type_code": 16,
        "ttl": 1,
        "packet_size": 280,
        "query_rate_per_sec": 45.0,
    }
    outlier_verdict = detector.evaluate(extreme_outlier)
    assert outlier_verdict.score > normal_verdict.score


def test_isolation_forest_save_and_load(tmp_path):
    """Verify model persistence to joblib and reloading."""
    model_file = str(tmp_path / "test_model.joblib")
    detector = IsolationForestDetector(model_path=model_file)

    benign_samples = [
        {"domain_length": 10, "subdomain_count": 0, "entropy": 2.5, "vowel_ratio": 0.5, "digit_ratio": 0.0, "max_consonant_sequence": 2, "query_type_code": 1, "ttl": 300, "packet_size": 64, "query_rate_per_sec": 0.1},
        {"domain_length": 12, "subdomain_count": 1, "entropy": 2.8, "vowel_ratio": 0.45, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 70, "query_rate_per_sec": 0.2},
        {"domain_length": 14, "subdomain_count": 1, "entropy": 2.9, "vowel_ratio": 0.40, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 72, "query_rate_per_sec": 0.1},
        {"domain_length": 11, "subdomain_count": 0, "entropy": 2.6, "vowel_ratio": 0.45, "digit_ratio": 0.0, "max_consonant_sequence": 2, "query_type_code": 1, "ttl": 300, "packet_size": 68, "query_rate_per_sec": 0.1},
        {"domain_length": 13, "subdomain_count": 1, "entropy": 2.7, "vowel_ratio": 0.42, "digit_ratio": 0.0, "max_consonant_sequence": 3, "query_type_code": 1, "ttl": 300, "packet_size": 69, "query_rate_per_sec": 0.1},
    ]

    detector.fit(benign_samples)
    saved_path = detector.save(model_file)
    assert os.path.exists(saved_path)

    # Reload into new detector instance
    new_detector = IsolationForestDetector(model_path=model_file)
    assert new_detector.is_trained is True
    assert new_detector.model is not None
