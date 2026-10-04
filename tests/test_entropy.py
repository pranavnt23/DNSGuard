"""
Unit tests for Shannon Entropy calculation in DNSGuard.
"""

import math
import pytest
from dns_engine.entropy import calculate_shannon_entropy, calculate_label_entropies, max_label_entropy


def test_entropy_empty_and_single_char():
    """Verify that empty strings or repetitive single-char strings yield 0.0 entropy."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy(None) == 0.0
    assert calculate_shannon_entropy("a") == 0.0
    assert calculate_shannon_entropy("aaaaaa") == 0.0


def test_entropy_distinct_characters():
    """Verify that an alphabet of 16 distinct chars yields log2(16) = 4.0 bits."""
    # 16 distinct characters: each has probability 1/16, so -16 * (1/16 * log2(1/16)) = 4.0
    text = "abcdefghijklmnop"
    assert calculate_shannon_entropy(text) == 4.0


def test_entropy_benign_vs_dga_benchmark():
    """Verify that natural language domains have lower entropy than high-randomness strings."""
    benign_entropy = calculate_shannon_entropy("google.com")
    dga_entropy = calculate_shannon_entropy("zk49wlmpt982xv.info")

    assert benign_entropy < 3.2
    assert dga_entropy > 3.5
    assert dga_entropy > benign_entropy


def test_label_entropies_and_max():
    """Verify label-wise entropy calculation."""
    domain = "aW5mby1leGZpbHRyYXRpb24.tunnel.evilcorp.net"
    label_entropies = calculate_label_entropies(domain)

    assert len(label_entropies) == 4
    # The first long base64-like label should have the highest entropy
    assert max_label_entropy(domain) == label_entropies[0]
    assert max_label_entropy(domain) > 3.8
