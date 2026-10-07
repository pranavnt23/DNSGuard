"""
Rule-Based DNS Tunneling & Data Exfiltration Detector for DNSGuard.

Combines multiple structural, statistical, and protocol signals:
- Unusually long DNS labels (approaching RFC 63-char limit)
- Hex / Base32 / Base64 encoded payload signatures
- High subdomain label Shannon entropy
- Deep subdomain hierarchy
- TXT query abuse with large wire lengths
- High query rate / velocity bursts

IMPORTANT: Never relies on entropy alone. Requires multiple corroborating
indicators to prevent false alarms on legitimate long CDN/cloud domains.
"""

from typing import Any, Dict, List, Optional
from database.models import DetectionType
from detection.rules import DetectionConfig, DetectorVerdict, RuleEvaluationResult


class DNSTunnelingDetector:
    """
    Detects covert DNS tunneling and data exfiltration through multi-signal correlation.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()

    def evaluate(self, features: Dict[str, Any]) -> DetectorVerdict:
        """
        Evaluates extracted feature dictionary against tunneling rules.

        Args:
            features: Dictionary of extracted lexical, structural, and behavioral features.

        Returns:
            DetectorVerdict: Structured verdict with suspicion score, confidence, and narrative.
        """
        triggered_rules: List[RuleEvaluationResult] = []
        evidence_list: List[str] = []

        # ----------------------------------------------------------------------
        # Rule 1: Longest Label Length (TUN-001)
        # ----------------------------------------------------------------------
        longest_label = int(features.get("longest_label_length") or 0)
        if longest_label >= self.config.tunneling_longest_label_threshold:
            ev = f"Unusually long subdomain label ({longest_label} chars >= {self.config.tunneling_longest_label_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-001",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=30.0,
                    evidence=ev,
                    explanation="Tunneling tools pack data into maximum-length labels to optimize throughput",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 2: Subdomain Label Entropy (TUN-002)
        # ----------------------------------------------------------------------
        label_entropy = float(features.get("max_label_entropy") or features.get("shannon_entropy") or 0.0)
        if label_entropy >= self.config.tunneling_max_label_entropy_threshold:
            ev = f"Elevated label Shannon entropy ({label_entropy:.2f} >= {self.config.tunneling_max_label_entropy_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-002",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=20.0,
                    evidence=ev,
                    explanation="Encrypted or compressed exfiltration payloads exhibit high character randomness",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 3: Hex / Base32 Encoded Payload Signature (TUN-003)
        # ----------------------------------------------------------------------
        has_hex_base32 = bool(features.get("has_hex_or_base32", False))
        if has_hex_base32:
            ev = "Label structure matches hexadecimal or Base32 encoding patterns"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-003",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=25.0,
                    evidence=ev,
                    explanation="Binary data must be encoded into DNS-safe character sets (Hex, Base32, Base64)",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 4: High Subdomain Nesting Depth (TUN-004)
        # ----------------------------------------------------------------------
        subdomain_depth = int(features.get("subdomain_depth") or features.get("subdomain_count") or 0)
        if subdomain_depth >= self.config.tunneling_subdomain_depth_threshold:
            ev = f"Deep subdomain hierarchy (depth={subdomain_depth} >= {self.config.tunneling_subdomain_depth_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-004",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=15.0,
                    evidence=ev,
                    explanation="Exfiltration utilities fragment data across multiple hierarchical labels",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 5: Overall Domain Length (TUN-005)
        # ----------------------------------------------------------------------
        domain_len = int(features.get("domain_length") or 0)
        if domain_len >= self.config.tunneling_domain_length_threshold:
            ev = f"Abnormally long total domain name ({domain_len} chars >= {self.config.tunneling_domain_length_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-005",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=15.0,
                    evidence=ev,
                    explanation="Exfiltration frames maximize available payload space within the 253-character domain limit",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 6: TXT Record Abuse with Large Wire Packet (TUN-006)
        # ----------------------------------------------------------------------
        qtype = str(features.get("query_type") or "").upper()
        pkt_len = int(features.get("packet_length") or 0)
        if qtype == "TXT" and pkt_len >= self.config.tunneling_large_packet_threshold:
            ev = f"Large TXT query payload size ({pkt_len} bytes >= {self.config.tunneling_large_packet_threshold}B)"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-006",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=25.0,
                    evidence=ev,
                    explanation="TXT queries are frequently abused by iodine/dnscat2 to tunnel bidirectional traffic",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 7: Burst Client Query Velocity (TUN-007)
        # ----------------------------------------------------------------------
        qrate = float(features.get("client_query_rate_per_sec") or 0.0)
        if qrate >= self.config.burst_query_rate_threshold:
            ev = f"High client query frequency ({qrate:.1f} qps >= {self.config.burst_query_rate_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="TUN-007",
                    threat_type=DetectionType.TUNNELING,
                    triggered=True,
                    weight=15.0,
                    evidence=ev,
                    explanation="Exfiltration streams generate high query velocity to transmit file chunks",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Multi-Signal Aggregation & False Positive Suppression
        # ----------------------------------------------------------------------
        raw_score = sum(r.weight for r in triggered_rules)
        normalized_score = round(min(100.0, raw_score), 2)

        # REQUIRE MULTIPLE INDICATORS:
        # A domain is only deemed suspicious if at least 2 distinct rules trigger AND
        # the aggregated score meets or exceeds the cutoff.
        indicator_count = len(triggered_rules)
        is_suspicious = (indicator_count >= 2 and normalized_score >= self.config.suspicious_score_cutoff)

        # Calculate confidence based on evidence convergence
        if is_suspicious:
            confidence = round(min(0.98, 0.40 + (indicator_count * 0.12)), 2)
            narrative = f"Possible DNS tunneling: Corroboration of {indicator_count} indicators ({', '.join(evidence_list[:3])})."
        elif indicator_count == 1:
            confidence = 0.25
            narrative = f"Benign/Inconclusive: Single isolated signal ({evidence_list[0]}), insufficient for tunneling verdict."
        else:
            confidence = 0.90
            narrative = "Benign: No structural, lexical, or volumetric tunneling indicators detected."

        return DetectorVerdict(
            threat_type=DetectionType.TUNNELING,
            is_suspicious=is_suspicious,
            score=normalized_score,
            confidence=confidence,
            evidence=evidence_list,
            reason=narrative,
            model_or_rule="RuleEngine:Tunneling_v1",
            details={
                "triggered_rules": [r.rule_id for r in triggered_rules],
                "indicator_count": indicator_count,
                "longest_label": longest_label,
                "has_hex_base32": has_hex_base32,
                "query_type": qtype,
            },
        )
