"""
Unit tests for DNS feature extraction in DNSGuard.
"""

import pytest
from dns_engine.features import extract_features, ClientActivityTracker


def test_lexical_feature_calculations():
    """Verify calculation of domain length, digit ratio, and vowel ratio."""
    model, details = extract_features(domain="login123.service.org", query_type="A")

    assert model.domain_length == len("login123.service.org")
    assert details["digit_count"] == 3  # '1', '2', '3'
    assert details["digit_ratio"] > 0.0
    assert details["vowel_ratio"] > 0.0
    assert model.query_type_code == 1  # A record


def test_subdomain_and_structural_features():
    """Verify subdomain depth and longest label calculations."""
    domain = "deep.sub4.sub3.sub2.sub1.target.com"
    model, details = extract_features(domain=domain)

    assert model.subdomain_count == 5
    assert details["longest_label_length"] == 6  # 'target'
    assert details["has_suspicious_long_label"] is False


def test_suspicious_tunneling_and_hex_heuristic():
    """Verify detection of suspiciously long label and hex/base32 pattern."""
    hex_label = "66696c652d646174612d657866696c74726174696f6e"  # 46 chars hex
    tunnel_domain = f"{hex_label}.tunnel.attacker.com"
    model, details = extract_features(domain=tunnel_domain, query_type="TXT")

    assert details["longest_label_length"] >= 40
    assert details["has_suspicious_long_label"] is True
    assert model.has_hex_or_base32 is True
    assert model.query_type_code == 16  # TXT record


def test_consecutive_consonant_clustering():
    """Verify consonant cluster tracking (DGA indicator)."""
    # 'bcdfghjk' is 8 consecutive consonants
    dga_like = "bcdfghjk123.biz"
    model, details = extract_features(domain=dga_like)

    assert model.max_consonant_sequence >= 8
    assert details["vowel_ratio"] <= 0.1


def test_client_activity_sliding_window():
    """Verify stateful velocity tracking for client query bursts."""
    tracker = ClientActivityTracker(window_seconds=10.0)
    client_ip = "192.168.1.200"

    # Simulate 5 queries in rapid succession
    for i in range(5):
        extract_features(
            domain="burst.test.org",
            client_id=client_ip,
            timestamp_epoch=100.0 + i,
            tracker=tracker,
        )

    # 6th query
    model, details = extract_features(
        domain="burst.test.org",
        client_id=client_ip,
        timestamp_epoch=105.0,
        tracker=tracker,
    )

    assert details["client_queries_in_window"] == 6
    assert details["repeated_query_count"] == 6
    assert details["client_query_rate_per_sec"] == 0.6  # 6 queries / 10s
