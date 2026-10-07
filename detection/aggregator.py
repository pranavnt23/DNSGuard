"""
Detection Result Aggregation Layer for DNSGuard.

Combines outputs from Tunneling, DGA, Spoofing, and Anomaly detectors into
a unified, cohesive detection verdict per DNS event.
Prepares structured outputs for downstream Prompt 4 risk scoring.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from database.models import DetectionResult, DetectionType
from detection.rules import DetectorVerdict


class UnifiedDetectionVerdict(BaseModel):
    """
    Consolidated threat analysis report for a single DNS event.
    Provides clear primary threat categorization, evidence synthesis, and explainability.
    """
    dns_event_id: Optional[int] = None
    domain: str
    client_identifier: str = Field(default="unknown")
    is_suspicious: bool = False
    primary_threat_type: Optional[DetectionType] = None
    secondary_threat_types: List[DetectionType] = Field(default_factory=list)
    overall_score: float = Field(ge=0.0, le=100.0, description="Highest calibrated suspicion score")
    confidence: float = Field(ge=0.0, le=1.0)
    detection_methods: List[str] = Field(default_factory=list, description="rule_based, machine_learning, etc.")
    all_evidence: List[str] = Field(default_factory=list)
    explanation: str
    individual_verdicts: Dict[str, DetectorVerdict] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = ConfigDict(from_attributes=True)


class DetectionAggregator:
    """
    Combines independent threat signals into a single explainable verdict.
    """

    @staticmethod
    def aggregate(
        domain: str,
        client_identifier: str,
        verdicts: List[DetectorVerdict],
        dns_event_id: Optional[int] = None,
    ) -> UnifiedDetectionVerdict:
        """
        Synthesizes individual detector verdicts into a unified threat report.

        Args:
            domain: The queried domain name.
            client_identifier: Host or client identifier.
            verdicts: List of DetectorVerdict objects from individual modules.
            dns_event_id: Optional database primary key of parent DNS event.

        Returns:
            UnifiedDetectionVerdict: Consolidated assessment.
        """
        verdicts_map: Dict[str, DetectorVerdict] = {v.threat_type.value: v for v in verdicts}
        suspicious_verdicts = [v for v in verdicts if v.is_suspicious]

        # Gather all evidence items and detection methods used
        all_evidence: List[str] = []
        methods_set = set()

        for v in verdicts:
            if "Rule" in v.model_or_rule:
                methods_set.add("rule_based")
            if "Model:" in v.model_or_rule or "IsolationForest" in v.model_or_rule:
                methods_set.add("machine_learning")
            if v.evidence:
                all_evidence.extend(v.evidence)

        if suspicious_verdicts:
            # Sort suspicious verdicts by score * confidence descending
            suspicious_verdicts.sort(key=lambda x: (x.score * x.confidence), reverse=True)
            primary = suspicious_verdicts[0]
            secondary = [v.threat_type for v in suspicious_verdicts[1:]]

            # Base score from strongest signal, with a small corroboration bonus if multiple threats fired
            base_score = primary.score
            multi_threat_bonus = min(10.0, (len(suspicious_verdicts) - 1) * 5.0)
            overall_score = round(min(100.0, base_score + multi_threat_bonus), 2)
            confidence = primary.confidence

            # Build explainable narrative
            ev_summary = "; ".join(primary.evidence[:3]) if primary.evidence else primary.reason
            narrative = f"Detected {primary.threat_type.value}: {ev_summary}."
            if secondary:
                sec_names = ", ".join(t.value for t in secondary)
                narrative += f" Corroborating secondary indicators: {sec_names}."

            return UnifiedDetectionVerdict(
                dns_event_id=dns_event_id,
                domain=domain,
                client_identifier=client_identifier,
                is_suspicious=True,
                primary_threat_type=primary.threat_type,
                secondary_threat_types=secondary,
                overall_score=overall_score,
                confidence=confidence,
                detection_methods=sorted(list(methods_set)),
                all_evidence=all_evidence,
                explanation=narrative,
                individual_verdicts=verdicts_map,
            )

        else:
            # Benign / Clean event
            highest_score_verdict = max(verdicts, key=lambda x: x.score) if verdicts else None
            top_score = highest_score_verdict.score if highest_score_verdict else 0.0

            return UnifiedDetectionVerdict(
                dns_event_id=dns_event_id,
                domain=domain,
                client_identifier=client_identifier,
                is_suspicious=False,
                primary_threat_type=None,
                secondary_threat_types=[],
                overall_score=top_score,
                confidence=0.92,
                detection_methods=sorted(list(methods_set)),
                all_evidence=[],
                explanation="Normal DNS traffic: No significant tunneling, DGA, spoofing, or anomaly indicators detected.",
                individual_verdicts=verdicts_map,
            )

    @staticmethod
    def to_database_models(
        verdict: UnifiedDetectionVerdict,
        dns_event_id: int,
    ) -> List[DetectionResult]:
        """
        Converts a UnifiedDetectionVerdict into canonical database DetectionResult rows
        ready for insertion into the SQLite 'detection_results' table.
        """
        db_results: List[DetectionResult] = []

        # Store individual detector verdicts so full breakdown is inspectable in DB
        for det_type_str, ind_verdict in verdict.individual_verdicts.items():
            db_results.append(
                DetectionResult(
                    dns_event_id=dns_event_id,
                    detection_type=ind_verdict.threat_type,
                    score=ind_verdict.score,
                    confidence=ind_verdict.confidence,
                    is_suspicious=ind_verdict.is_suspicious,
                    reason=ind_verdict.reason,
                    model_or_rule=ind_verdict.model_or_rule,
                    details=ind_verdict.details,
                    timestamp=verdict.timestamp,
                )
            )

        return db_results
