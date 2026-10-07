"""
Comprehensive DNS Feature Extraction Engine for DNSGuard.

Extracts deterministic lexical, structural, statistical, and behavioral features
from DNS queries and responses to drive rule-based and ML threat detection.
"""

import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from database.models import ExtractedFeatures
from dns_engine.entropy import calculate_shannon_entropy, max_label_entropy
from dns_engine.normalizer import normalize_domain, NormalizedDomain

# Standard DNS RR Type mappings (RFC 1035, RFC 3596, etc.)
RR_TYPE_MAP: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255,
}

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{8,}$")
BASE32_PATTERN = re.compile(r"^[a-z2-7=]{12,}$", re.IGNORECASE)


class ClientActivityTracker:
    """
    Sliding-window in-memory state tracker for DNS client query velocity and frequency.
    Maintains timestamped query history to compute rate and burst metrics.
    """

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        # client_id -> list of (timestamp_epoch, domain)
        self._client_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        # domain -> list of timestamp_epoch
        self._domain_history: Dict[str, List[float]] = defaultdict(list)

    def record_query(
        self,
        client_id: str,
        domain: str,
        timestamp_epoch: Optional[float] = None,
    ) -> Tuple[float, int, int, int]:
        """
        Records a query event and computes velocity statistics.

        Returns:
            Tuple[float, int, int, int]:
                - query_rate_per_sec (for client)
                - queries_for_client_in_window
                - queries_for_domain_in_window
                - repeated_domain_count_by_client
        """
        now = timestamp_epoch if timestamp_epoch is not None else time.time()
        cutoff = now - self.window_seconds

        # Prune and update client records
        c_records = self._client_history[client_id]
        c_records = [rec for rec in c_records if rec[0] >= cutoff]
        c_records.append((now, domain))
        self._client_history[client_id] = c_records

        # Prune and update domain records
        d_records = self._domain_history[domain]
        d_records = [t for t in d_records if t >= cutoff]
        d_records.append(now)
        self._domain_history[domain] = d_records

        client_count = len(c_records)
        domain_count = len(d_records)
        repeated_for_client = sum(1 for _, d in c_records if d == domain)
        query_rate = round(client_count / max(self.window_seconds, 1.0), 3)

        return query_rate, client_count, domain_count, repeated_for_client

    def clear(self) -> None:
        """Resets tracker state."""
        self._client_history.clear()
        self._domain_history.clear()


# Global default tracker instance
_default_tracker = ClientActivityTracker(window_seconds=60.0)


def get_activity_tracker() -> ClientActivityTracker:
    """Returns the central client activity tracker."""
    return _default_tracker


def _max_consecutive_consonants(text: str) -> int:
    """Computes the length of the longest consecutive run of consonants."""
    max_run = 0
    current_run = 0
    for char in text.lower():
        if char in CONSONANTS:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0
    return max_run


def _is_hex_or_base32_like(labels: List[str]) -> bool:
    """Checks whether any subdomain label resembles a hex or base32-encoded tunneling chunk."""
    for label in labels:
        if len(label) >= 10:
            if HEX_PATTERN.match(label) or BASE32_PATTERN.match(label):
                return True
    return False


def extract_features(
    domain: str,
    query_type: str = "A",
    response_code: Optional[str] = "NOERROR",
    response_data: Optional[List[str]] = None,
    ttl: Optional[int] = None,
    packet_length: Optional[int] = None,
    client_id: Optional[str] = None,
    timestamp_epoch: Optional[float] = None,
    tracker: Optional[ClientActivityTracker] = None,
) -> Tuple[ExtractedFeatures, Dict[str, Any]]:
    """
    Extracts complete feature vectors from a DNS event.

    Args:
        domain: Domain name (raw or normalized).
        query_type: DNS RR query type string (e.g. 'A', 'AAAA', 'TXT').
        response_code: DNS RCODE (e.g. 'NOERROR', 'NXDOMAIN').
        response_data: List of resolved IP addresses or answer strings.
        ttl: Time-To-Live in seconds.
        packet_length: Total wire packet length in bytes.
        client_id: Client identifier or IP for sliding-window velocity.
        timestamp_epoch: Optional epoch timestamp for deterministic historical testing.
        tracker: Optional custom activity tracker (uses default if None).

    Returns:
        Tuple:
            - ExtractedFeatures: Canonical Pydantic model for database storage and ML.
            - Dict[str, Any]: Comprehensive dictionary containing all raw metrics and sub-features.
    """
    norm: NormalizedDomain = normalize_domain(domain)
    clean_domain = norm.normalized_domain
    labels = norm.labels
    domain_len = len(clean_domain)

    # --------------------------------------------------------------------------
    # A. Lexical Features
    # --------------------------------------------------------------------------
    digit_count = sum(c.isdigit() for c in clean_domain)
    alpha_count = sum(c.isalpha() for c in clean_domain)
    vowel_count = sum(c in VOWELS for c in clean_domain.lower())
    special_count = sum(not c.isalnum() for c in clean_domain)  # dots, hyphens, etc.

    digit_ratio = round(digit_count / max(domain_len, 1), 4)
    vowel_ratio = round(vowel_count / max(alpha_count, 1), 4)
    character_diversity = round(len(set(clean_domain)) / max(domain_len, 1), 4)

    shannon_entropy = calculate_shannon_entropy(clean_domain)
    max_lbl_entropy = max_label_entropy(clean_domain)
    max_consonants = _max_consecutive_consonants(clean_domain)

    # --------------------------------------------------------------------------
    # B. Domain Structure Features
    # --------------------------------------------------------------------------
    label_count = len(labels)
    subdomain_depth = norm.subdomain_depth
    longest_label_len = max((len(lbl) for lbl in labels), default=0)
    has_suspicious_long_label = longest_label_len >= 40  # DNS tunneling threshold
    has_hex_base32 = _is_hex_or_base32_like(labels)

    # --------------------------------------------------------------------------
    # C. DNS Behavioral & Protocol Features
    # --------------------------------------------------------------------------
    qtype_upper = (query_type or "A").upper().strip()
    qtype_code = RR_TYPE_MAP.get(qtype_upper, 1)
    answers_count = len(response_data) if response_data else 0
    wire_size = int(packet_length or (domain_len + 32))

    # --------------------------------------------------------------------------
    # D. Sliding-Window Client Velocity Features
    # --------------------------------------------------------------------------
    active_tracker = tracker or _default_tracker
    cid = client_id or "default_client"

    if client_id:
        q_rate, c_window, d_window, repeated_cnt = active_tracker.record_query(
            client_id=cid,
            domain=clean_domain,
            timestamp_epoch=timestamp_epoch,
        )
    else:
        q_rate, c_window, d_window, repeated_cnt = 0.0, 1, 1, 1

    # --------------------------------------------------------------------------
    # Canonical ExtractedFeatures Model
    # --------------------------------------------------------------------------
    features_model = ExtractedFeatures(
        domain_length=domain_len,
        subdomain_count=subdomain_depth,
        entropy=shannon_entropy,
        vowel_ratio=vowel_ratio,
        digit_ratio=digit_ratio,
        max_consonant_sequence=max_consonants,
        has_hex_or_base32=has_hex_base32,
        query_type_code=qtype_code,
        ttl_value=ttl,
        packet_size=wire_size,
        response_count=answers_count,
        query_rate_per_sec=q_rate,
    )

    # Comprehensive dictionary for audit and full inspection
    extended_details: Dict[str, Any] = {
        "domain_length": domain_len,
        "label_count": label_count,
        "subdomain_depth": subdomain_depth,
        "longest_label_length": longest_label_len,
        "has_suspicious_long_label": has_suspicious_long_label,
        "shannon_entropy": shannon_entropy,
        "max_label_entropy": max_lbl_entropy,
        "digit_count": digit_count,
        "alpha_count": alpha_count,
        "special_char_count": special_count,
        "digit_ratio": digit_ratio,
        "vowel_ratio": vowel_ratio,
        "character_diversity": character_diversity,
        "max_consonant_sequence": max_consonants,
        "has_hex_or_base32": has_hex_base32,
        "query_type": qtype_upper,
        "query_type_code": qtype_code,
        "response_code": response_code or "UNKNOWN",
        "response_data": response_data or [],
        "ttl": ttl,
        "response_count": answers_count,
        "packet_length": wire_size,
        "client_query_rate_per_sec": q_rate,
        "client_queries_in_window": c_window,
        "domain_queries_in_window": d_window,
        "repeated_query_count": repeated_cnt,
        "is_structurally_valid": norm.is_valid,
        "tld": norm.tld,
        "sld": norm.sld,
    }

    return features_model, extended_details
