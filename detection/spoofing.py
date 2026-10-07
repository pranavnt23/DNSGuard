"""
DNS Spoofing & Cache Poisoning Inconsistency Detector for DNSGuard.

Detects response discrepancies and cache tampering indicators:
- Abrupt TTL drops (Kaminsky cache poisoning / rapid eviction artifacts)
- Unexplained disjoint IP address shifts across queries
- Conflicting resolution outcomes from different resolvers
- DNSSEC signature validation failures

IMPORTANT: Legitimate CDNs and load-balancers frequently rotate IP addresses.
This detector flags 'Possible DNS response inconsistency' with explainable evidence
rather than claiming definitive attribution.
"""

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from database.models import DetectionType
from detection.dnssec import DNSSECStatus, evaluate_dnssec
from detection.rules import DetectionConfig, DetectorVerdict, RuleEvaluationResult


class HistoricalObservation:
    """Snapshot of a previously resolved domain observation."""
    def __init__(self, timestamp: float, ips: Set[str], ttl: Optional[int], resolver: str):
        self.timestamp = timestamp
        self.ips = ips
        self.ttl = ttl
        self.resolver = resolver


class ResponseConsistencyTracker:
    """
    Maintains a rolling historical cache of domain resolutions to enable
    comparative inconsistency analysis between successive queries.
    """

    def __init__(self, max_history_per_domain: int = 10):
        self.max_history = max_history_per_domain
        self._history: Dict[str, List[HistoricalObservation]] = defaultdict(list)

    def record_and_compare(
        self,
        domain: str,
        current_ips: List[str],
        current_ttl: Optional[int],
        resolver: str,
        timestamp_epoch: Optional[float] = None,
    ) -> Tuple[Optional[HistoricalObservation], Dict[str, Any]]:
        """
        Records an observation and compares it against prior queries for the same domain.

        Returns:
            Tuple: (previous_observation, comparative_metrics_dict)
        """
        now = timestamp_epoch if timestamp_epoch is not None else time.time()
        clean_domain = domain.strip().rstrip(".").lower()
        domain_history = self._history[clean_domain]

        prev_obs: Optional[HistoricalObservation] = domain_history[-1] if domain_history else None

        current_ip_set = set(current_ips)
        metrics: Dict[str, Any] = {
            "has_prior_history": prev_obs is not None,
            "ttl_dropped_abruptly": False,
            "ip_set_disjoint": False,
            "resolver_changed": False,
            "prior_ttl": prev_obs.ttl if prev_obs else None,
            "prior_ips": list(prev_obs.ips) if prev_obs else [],
        }

        if prev_obs:
            # Check 1: Abrupt TTL drop (e.g. 300s -> <= 5s)
            if prev_obs.ttl and current_ttl is not None:
                if prev_obs.ttl >= 60 and current_ttl <= 5:
                    metrics["ttl_dropped_abruptly"] = True

            # Check 2: IP address set change
            if prev_obs.ips and current_ip_set:
                # Disjoint if no intersection between old and new IP sets
                if not prev_obs.ips.intersection(current_ip_set):
                    metrics["ip_set_disjoint"] = True

            # Check 3: Resolver discrepancy
            if prev_obs.resolver and resolver and prev_obs.resolver != resolver:
                metrics["resolver_changed"] = True

        # Append current observation and prune excess history
        domain_history.append(
            HistoricalObservation(
                timestamp=now,
                ips=current_ip_set,
                ttl=current_ttl,
                resolver=resolver,
            )
        )
        if len(domain_history) > self.max_history:
            self._history[clean_domain] = domain_history[-self.max_history:]

        return prev_obs, metrics

    def clear(self) -> None:
        """Resets tracker state."""
        self._history.clear()


# Central singleton tracker
_default_consistency_tracker = ResponseConsistencyTracker()


def get_consistency_tracker() -> ResponseConsistencyTracker:
    """Returns the central domain consistency tracker."""
    return _default_consistency_tracker


class DNSSpoofingDetector:
    """
    Detects potential cache poisoning and response inconsistency indicators.
    """

    def __init__(
        self,
        config: Optional[DetectionConfig] = None,
        tracker: Optional[ResponseConsistencyTracker] = None,
    ):
        self.config = config or DetectionConfig()
        self.tracker = tracker or _default_consistency_tracker

    def evaluate(self, features: Dict[str, Any]) -> DetectorVerdict:
        """
        Evaluates a DNS event for cache poisoning or response inconsistency indicators.

        Args:
            features: Dictionary of event metadata.

        Returns:
            DetectorVerdict: Structured verdict with explicit evidence.
        """
        domain = str(features.get("domain") or features.get("queried_domain") or "")
        current_ips = features.get("response_data") or []
        if isinstance(current_ips, str):
            current_ips = [ip.strip() for ip in current_ips.split(",") if ip.strip()]

        current_ttl = features.get("ttl")
        if current_ttl is not None:
            try:
                current_ttl = int(current_ttl)
            except (ValueError, TypeError):
                current_ttl = None

        resolver = str(features.get("destination_ip") or "8.8.8.8")
        timestamp_epoch = features.get("timestamp_epoch")

        prev_obs, comp = self.tracker.record_and_compare(
            domain=domain,
            current_ips=current_ips,
            current_ttl=current_ttl,
            resolver=resolver,
            timestamp_epoch=timestamp_epoch,
        )

        triggered_rules: List[RuleEvaluationResult] = []
        evidence_list: List[str] = []

        # ----------------------------------------------------------------------
        # Rule 1: Abrupt TTL Drop (SPF-001)
        # ----------------------------------------------------------------------
        if comp["ttl_dropped_abruptly"]:
            ev = f"Abrupt TTL reduction (prior TTL={comp['prior_ttl']}s -> current TTL={current_ttl}s)"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="SPF-001",
                    threat_type=DetectionType.SPOOFING,
                    triggered=True,
                    weight=35.0,
                    evidence=ev,
                    explanation="Cache poisoning exploits often inject short TTLs to force frequent vulnerable re-queries",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 2: Anomalously Low TTL Floor (SPF-002)
        # ----------------------------------------------------------------------
        if current_ttl is not None and current_ttl <= self.config.spoofing_ttl_drop_threshold:
            # Low TTL is an indicator, but only if not already counted by abrupt drop
            if not comp["ttl_dropped_abruptly"]:
                ev = f"Anomalously low TTL observed ({current_ttl}s <= {self.config.spoofing_ttl_drop_threshold}s)"
                triggered_rules.append(
                    RuleEvaluationResult(
                        rule_id="SPF-002",
                        threat_type=DetectionType.SPOOFING,
                        triggered=True,
                        weight=20.0,
                        evidence=ev,
                        explanation="Artificially low TTLs can signal fast-flux botnets or cache replacement attempts",
                    )
                )
                evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 3: Disjoint IP Set Inconsistency (SPF-003)
        # ----------------------------------------------------------------------
        if comp["ip_set_disjoint"] and comp["resolver_changed"]:
            ev = f"Conflicting IP answers from different resolvers ({resolver} vs {prev_obs.resolver if prev_obs else 'prior'})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="SPF-003",
                    threat_type=DetectionType.SPOOFING,
                    triggered=True,
                    weight=30.0,
                    evidence=ev,
                    explanation="Mismatched resolver answers may indicate an unauthoritative spoofed reply",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 4: DNSSEC Signature Validation Failure (SPF-004)
        # ----------------------------------------------------------------------
        dnssec_res = evaluate_dnssec(event_data=features)
        if dnssec_res.status == DNSSECStatus.INVALID:
            ev = f"DNSSEC validation failure: {dnssec_res.reason}"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="SPF-004",
                    threat_type=DetectionType.SPOOFING,
                    triggered=True,
                    weight=45.0,
                    evidence=ev,
                    explanation="Cryptographic signature verification failed; records were modified in flight",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Scoring & Reporting
        # ----------------------------------------------------------------------
        total_score = round(min(100.0, sum(r.weight for r in triggered_rules)), 2)
        is_suspicious = (len(triggered_rules) >= 1 and total_score >= self.config.suspicious_score_cutoff)

        if is_suspicious:
            confidence = round(min(0.95, 0.40 + (len(triggered_rules) * 0.15)), 2)
            narrative = f"Possible DNS response inconsistency: {'; '.join(evidence_list)}."
        elif triggered_rules:
            confidence = 0.30
            narrative = f"Benign/Inconclusive response variance: {evidence_list[0]} (likely CDN or dynamic TTL)."
        else:
            confidence = 0.90
            narrative = "Benign: Response parameters and TTL consistent with baseline DNS behavior."

        return DetectorVerdict(
            threat_type=DetectionType.SPOOFING,
            is_suspicious=is_suspicious,
            score=total_score,
            confidence=confidence,
            evidence=evidence_list,
            reason=narrative,
            model_or_rule="RuleEngine:SpoofingInconsistency_v1",
            details={
                "triggered_rules": [r.rule_id for r in triggered_rules],
                "comparative_metrics": comp,
                "dnssec_status": dnssec_res.status.value,
            },
        )
