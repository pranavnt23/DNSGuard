"""
Shannon Entropy calculation module for DNSGuard.

Mathematical Formulation:
    H(X) = - Σ p(x) * log2(p(x))
    where p(x) is the empirical probability of character x occurring in string X.

Important Security & Academic Context:
    Shannon entropy measures the informational randomness and unpredictability
    of a character sequence. In DNS threat detection:
    - Normal human-registered domains (e.g., 'google.com', 'wikipedia.org') typically
      exhibit entropy between 2.2 and 3.2 because they conform to phonological
      conventions of natural human languages.
    - Algorithmically Generated Domains (DGA) used by malware command-and-control
      often exhibit higher entropy (> 3.8) due to pseudo-random character selection.
    - CRITICAL LIMITATION: High entropy is an informative signal/feature, NOT definitive
      proof of maliciousness. Certain legitimate services (Content Delivery Networks,
      Cloud load balancers, cryptographic identifier domains like 'd3v5k9.cloudfront.net')
      naturally display elevated entropy. Conversely, dictionary-based DGAs (e.g., Suppobox)
      concatenate natural words and maintain low entropy. Therefore, entropy must be
      combined with other structural, lexical, and behavioral features in the risk engine.
"""

import math
from collections import Counter
from typing import List, Optional


def calculate_shannon_entropy(text: Optional[str]) -> float:
    """
    Computes the Shannon entropy (in bits per character) for a given string.

    Args:
        text: The string to evaluate (e.g., domain name or label).

    Returns:
        float: Entropy value >= 0.0 rounded to 4 decimal places.
               Returns 0.0 for empty strings or strings with only 1 distinct character.

    Examples:
        >>> calculate_shannon_entropy("")
        0.0
        >>> calculate_shannon_entropy("aaaa")
        0.0
        >>> calculate_shannon_entropy("abcdefghijklmnop") # 16 unique characters
        4.0
    """
    if not text:
        return 0.0

    length = len(text)
    if length <= 1:
        return 0.0

    frequencies = Counter(text)
    entropy = 0.0

    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    # Clean up minor floating point imprecision (-0.0)
    return round(max(0.0, entropy), 4)


def calculate_label_entropies(domain: Optional[str]) -> List[float]:
    """
    Computes Shannon entropy individually for each dot-separated label in a domain.

    Args:
        domain: Fully qualified or partial domain string (e.g. 'sub.example.com').

    Returns:
        List[float]: List of entropy values corresponding to each label from left to right.
    """
    if not domain:
        return []

    clean_domain = domain.strip().rstrip(".")
    if not clean_domain:
        return []

    labels = clean_domain.split(".")
    return [calculate_shannon_entropy(label) for label in labels if label]


def max_label_entropy(domain: Optional[str]) -> float:
    """
    Computes the maximum Shannon entropy observed across all individual labels.
    Useful for detecting high-entropy subdomain payloads in DNS tunneling
    even when the registered domain (SLD) looks ordinary.

    Args:
        domain: The domain name string.

    Returns:
        float: Maximum entropy among all labels, or 0.0 if empty.
    """
    entropies = calculate_label_entropies(domain)
    return max(entropies) if entropies else 0.0
