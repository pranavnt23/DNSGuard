"""
Unit tests for DNS Tunneling detection module in DNSGuard.
"""

import pytest
from database.models import DetectionType
from detection.rules import DetectionConfig
from detection.tunneling import DNSTunnelingDetector


def test_tunneling_detection_positive():
    """Verify that a domain with multiple tunneling signals is flagged."""
    detector = DNSTunnelingDetector()
    tunneling_features = {
        "longest_label_length": 46,
        "max_label_entropy": 4.15,
        "has_hex_or_base32": True,
        "domain_length": 62,
        "subdomain_depth": 3,
        "query_type": "TXT",
        "packet_length": 145,
    }

    verdict = detector.evaluate(tunneling_features)
    assert verdict.is_suspicious is True
    assert verdict.threat_type == DetectionType.TUNNELING
    assert verdict.score >= 50.0
    assert len(verdict.evidence) >= 3
    assert "tunneling" in verdict.reason.lower()


def test_tunneling_detection_negative_benign():
    """Verify that standard normal domains do not trigger tunneling."""
    detector = DNSTunnelingDetector()
    benign_features = {
        "longest_label_length": 6,  # 'google'
        "max_label_entropy": 2.5,
        "has_hex_or_base32": False,
        "domain_length": 10,
        "subdomain_depth": 0,
        "query_type": "A",
        "packet_length": 64,
    }

    verdict = detector.evaluate(benign_features)
    assert verdict.is_suspicious is False
    assert verdict.score == 0.0
    assert "benign" in verdict.reason.lower()


def test_tunneling_false_positive_suppression_isolated_entropy():
    """Verify that isolated high entropy on a short label does NOT trigger tunneling without corroborating evidence."""
    detector = DNSTunnelingDetector()
    isolated_features = {
        "longest_label_length": 8,  # short label
        "max_label_entropy": 4.2,   # high entropy alone
        "has_hex_or_base32": False,
        "domain_length": 18,
        "subdomain_depth": 1,
        "query_type": "A",
        "packet_length": 65,
    }

    verdict = detector.evaluate(isolated_features)
    # Must NOT be marked suspicious on single isolated signal
    assert verdict.is_suspicious is False
    assert "insufficient" in verdict.reason.lower() or "benign" in verdict.reason.lower()


def test_tunneling_custom_config_override():
    """Verify that configurable thresholds correctly adjust sensitivity."""
    custom_cfg = DetectionConfig(tunneling_longest_label_threshold=20)
    detector = DNSTunnelingDetector(config=custom_cfg)

    features = {
        "longest_label_length": 25,
        "domain_length": 35,
        "has_hex_or_base32": True,
    }
    verdict = detector.evaluate(features)
    assert verdict.score >= 40.0
