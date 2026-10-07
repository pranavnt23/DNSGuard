"""
Unit tests for DGA and suspicious domain detection module in DNSGuard.
"""

import pytest
from database.models import DetectionType
from detection.dga import DGADetector
from detection.rules import DetectionConfig


def test_dga_detection_positive_high_entropy_and_consonants():
    """Verify that a DGA domain with elevated entropy and consonant clustering is detected."""
    detector = DGADetector()
    dga_features = {
        "domain": "zk49wlmpt982xv.info",
        "domain_length": 19,
        "shannon_entropy": 4.14,
        "vowel_ratio": 0.08,
        "max_consonant_sequence": 6,
        "digit_ratio": 0.25,
        "character_diversity": 0.85,
        "alpha_count": 12,
        "response_code": "NXDOMAIN",
    }

    verdict = detector.evaluate(dga_features)
    assert verdict.is_suspicious is True
    assert verdict.threat_type == DetectionType.DGA
    assert verdict.score >= 50.0
    assert len(verdict.evidence) >= 2
    assert "dga" in verdict.reason.lower()


def test_dga_detection_negative_benign():
    """Verify that natural language popular domains are classified as clean."""
    detector = DGADetector()
    benign_features = {
        "domain": "wikipedia.org",
        "domain_length": 13,
        "shannon_entropy": 2.85,
        "vowel_ratio": 0.50,
        "max_consonant_sequence": 2,
        "digit_ratio": 0.0,
        "character_diversity": 0.65,
        "alpha_count": 12,
        "response_code": "NOERROR",
    }

    verdict = detector.evaluate(benign_features)
    assert verdict.is_suspicious is False
    assert verdict.score == 0.0
    assert "benign" in verdict.reason.lower()


def test_dga_short_domain_entropy_suppression():
    """Verify that very short domains (e.g. 4-6 chars) do not trigger false positive DGA alarms."""
    detector = DGADetector()
    short_domain_features = {
        "domain": "t.co",
        "domain_length": 4,
        "shannon_entropy": 3.9,
        "vowel_ratio": 0.33,
        "max_consonant_sequence": 1,
        "digit_ratio": 0.0,
        "alpha_count": 3,
        "response_code": "NOERROR",
    }

    verdict = detector.evaluate(short_domain_features)
    assert verdict.is_suspicious is False


def test_dga_ml_anomaly_blending():
    """Verify that external ML anomaly input blends into the DGA score."""
    detector = DGADetector()
    borderline_features = {
        "domain": "somewhat-unusual-host.net",
        "domain_length": 25,
        "shannon_entropy": 3.85,
        "vowel_ratio": 0.30,
        "max_consonant_sequence": 3,
        "digit_ratio": 0.0,
        "alpha_count": 20,
    }

    # Without ML anomaly
    v1 = detector.evaluate(borderline_features, ml_anomaly_score=None)
    # With high ML anomaly
    v2 = detector.evaluate(borderline_features, ml_anomaly_score=75.0)

    assert v2.score > v1.score
    assert any("ML Anomaly" in ev for ev in v2.evidence)
