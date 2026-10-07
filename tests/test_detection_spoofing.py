"""
Unit tests for DNS Spoofing and response consistency detection in DNSGuard.
"""

import pytest
from database.models import DetectionType
from detection.dnssec import DNSSECStatus, evaluate_dnssec
from detection.spoofing import DNSSpoofingDetector, ResponseConsistencyTracker


def test_spoofing_abrupt_ttl_drop_detection():
    """Verify that an abrupt TTL reduction on consecutive queries triggers a spoofing alert."""
    tracker = ResponseConsistencyTracker()
    detector = DNSSpoofingDetector(tracker=tracker)

    domain = "secure-portal.bank.com"

    # Query 1: Normal baseline resolution
    query1 = {
        "domain": domain,
        "response_data": ["198.51.100.1"],
        "ttl": 300,
        "destination_ip": "8.8.8.8",
        "timestamp_epoch": 1000.0,
    }
    detector.evaluate(query1)

    # Query 2: Abrupt TTL drop to 1s
    query2 = {
        "domain": domain,
        "response_data": ["203.0.113.50"],
        "ttl": 1,
        "destination_ip": "198.51.100.200",  # Changed resolver
        "timestamp_epoch": 1005.0,
    }
    verdict = detector.evaluate(query2)

    assert verdict.is_suspicious is True
    assert verdict.threat_type == DetectionType.SPOOFING
    assert verdict.score >= 50.0
    assert any("TTL reduction" in ev for ev in verdict.evidence)


def test_spoofing_benign_consistent_resolution():
    """Verify that repeated consistent resolutions remain clean."""
    tracker = ResponseConsistencyTracker()
    detector = DNSSpoofingDetector(tracker=tracker)

    domain = "api.github.com"
    for i in range(3):
        query = {
            "domain": domain,
            "response_data": ["140.82.112.4"],
            "ttl": 60,
            "destination_ip": "8.8.8.8",
            "timestamp_epoch": 2000.0 + i,
        }
        verdict = detector.evaluate(query)

    assert verdict.is_suspicious is False
    assert "consistent" in verdict.reason.lower()


def test_dnssec_evaluation_states():
    """Verify tri-state DNSSEC evaluation logic (VALID, INVALID, UNKNOWN)."""
    # 1. Invalid / BOGUS
    res_invalid = evaluate_dnssec(event_data={"dnssec_status": "invalid"})
    assert res_invalid.status == DNSSECStatus.INVALID

    # 2. Valid
    res_valid = evaluate_dnssec(event_data={"dnssec_status": "valid"})
    assert res_valid.status == DNSSECStatus.VALID

    # 3. Missing / Unknown (never treated as invalid)
    res_unknown = evaluate_dnssec(event_data={})
    assert res_unknown.status == DNSSECStatus.UNKNOWN
    assert res_unknown.status != DNSSECStatus.INVALID
