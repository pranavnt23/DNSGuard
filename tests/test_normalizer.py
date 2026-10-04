"""
Unit tests for domain normalization and RFC validation in DNSGuard.
"""

import pytest
from dns_engine.normalizer import normalize_domain, clean_domain_string


def test_trailing_dot_and_case_normalization():
    """Verify stripping of trailing dots and case normalization."""
    res = normalize_domain("EXAMPLE.COM.")
    assert res.normalized_domain == "example.com"
    assert res.raw_domain == "EXAMPLE.COM."
    assert res.tld == "com"
    assert res.sld == "example"
    assert res.is_valid is True


def test_whitespace_and_empty_domain():
    """Verify safe handling of whitespace and empty inputs."""
    assert clean_domain_string("   test.org.   ") == "test.org"
    empty_norm = normalize_domain("")
    assert empty_norm.is_valid is False
    assert empty_norm.normalized_domain == ""

    none_norm = normalize_domain(None)
    assert none_norm.is_valid is False
    assert none_norm.normalized_domain == ""


def test_subdomain_depth_extraction():
    """Verify subdomain extraction across multiple levels."""
    res = normalize_domain("edge.cdn.us-east.prod.service.net")
    assert res.tld == "net"
    assert res.sld == "service"
    assert res.subdomains == ["edge", "cdn", "us-east", "prod"]
    assert res.subdomain_depth == 4


def test_multi_part_tld_handling():
    """Verify recognition of multi-part country code TLDs like .co.uk."""
    res = normalize_domain("news.bbc.co.uk")
    assert res.tld == "co.uk"
    assert res.sld == "bbc"
    assert res.subdomains == ["news"]
    assert res.subdomain_depth == 1


def test_consecutive_dots_invalid():
    """Verify that malformed domains with consecutive dots are flagged."""
    res = normalize_domain("bad..domain.com")
    assert res.is_valid is False
    assert "consecutive" in res.error_message.lower()


def test_rfc_label_length_limits():
    """Verify RFC 1035 max 63 chars per label constraint."""
    long_label = "a" * 64
    res = normalize_domain(f"{long_label}.com")
    assert res.is_valid is False
    assert "exceeds 63" in res.error_message.lower()
