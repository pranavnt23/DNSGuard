"""
DGA (Domain Generation Algorithm) & Suspicious Domain Detector for DNSGuard.

Evaluates phonological, lexical, and statistical randomness metrics:
- Shannon entropy (bits per character)
- Consonant-to-vowel distribution and consonant cluster runs
- Digit ratio and character diversity
- NXDOMAIN storm response patterns
- Domain registration recency (when context is available)

Combines multi-factor rule scoring with optional machine learning anomaly input.
"""

from typing import Any, Dict, List, Optional
from database.models import DetectionType
from detection.rules import DetectionConfig, DetectorVerdict, RuleEvaluationResult


class DGADetector:
    """
    Detects algorithmically generated and pseudo-random domains using explainable lexical features.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()

    def evaluate(
        self,
        features: Dict[str, Any],
        ml_anomaly_score: Optional[float] = None,
    ) -> DetectorVerdict:
        """
        Evaluates domain features against DGA heuristics and phonotactic rules.

        Args:
            features: Dictionary of extracted domain features.
            ml_anomaly_score: Optional normalized anomaly score from ML detector (0 to 100).

        Returns:
            DetectorVerdict: Structured verdict with explainable evidence and score.
        """
        domain = str(features.get("domain") or features.get("queried_domain") or "")
        domain_len = int(features.get("domain_length") or len(domain))
        triggered_rules: List[RuleEvaluationResult] = []
        evidence_list: List[str] = []

        # ----------------------------------------------------------------------
        # Rule 1: Shannon Entropy (DGA-001)
        # ----------------------------------------------------------------------
        entropy = float(features.get("shannon_entropy") or features.get("entropy") or 0.0)
        if entropy >= self.config.dga_entropy_threshold and domain_len >= 8:
            ev = f"Elevated Shannon entropy ({entropy:.2f} >= {self.config.dga_entropy_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-001",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=30.0,
                    evidence=ev,
                    explanation="Pseudo-random generation yields higher entropy than natural human languages",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 2: Low Vowel Ratio (DGA-002)
        # ----------------------------------------------------------------------
        vowel_ratio = float(features.get("vowel_ratio") if features.get("vowel_ratio") is not None else 0.5)
        alpha_count = int(features.get("alpha_count") or 1)
        if vowel_ratio <= self.config.dga_vowel_ratio_threshold and alpha_count >= 5:
            ev = f"Sparse vowel ratio ({vowel_ratio:.2f} <= {self.config.dga_vowel_ratio_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-002",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=25.0,
                    evidence=ev,
                    explanation="Natural English vocabulary requires vowels; DGA sequences frequently omit them",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 3: Consecutive Consonant Run (DGA-003)
        # ----------------------------------------------------------------------
        consonant_run = int(features.get("max_consonant_sequence") or 0)
        if consonant_run >= self.config.dga_consonant_run_threshold:
            ev = f"Unnatural consonant cluster ({consonant_run} consonants >= {self.config.dga_consonant_run_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-003",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=25.0,
                    evidence=ev,
                    explanation="Long consecutive consonant runs violate standard Indo-European phonotactics",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 4: Elevated Digit Ratio (DGA-004)
        # ----------------------------------------------------------------------
        digit_ratio = float(features.get("digit_ratio") or 0.0)
        if digit_ratio >= self.config.dga_digit_ratio_threshold:
            ev = f"High proportion of numeric digits ({digit_ratio:.2f} >= {self.config.dga_digit_ratio_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-004",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=20.0,
                    evidence=ev,
                    explanation="Alphanumeric DGAs frequently interleave numbers into domain labels",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 5: Character Diversity (DGA-005)
        # ----------------------------------------------------------------------
        char_diversity = float(features.get("character_diversity") or 0.0)
        if char_diversity >= self.config.dga_diversity_threshold and domain_len >= 12:
            ev = f"High character diversity ({char_diversity:.2f} >= {self.config.dga_diversity_threshold})"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-005",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=15.0,
                    evidence=ev,
                    explanation="Random generators draw from broad character distributions without repetitive n-grams",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 6: NXDOMAIN Response Pattern (DGA-006)
        # ----------------------------------------------------------------------
        rcode = str(features.get("response_code") or "").upper()
        if rcode == "NXDOMAIN":
            ev = "Resolution resulted in NXDOMAIN (Non-Existent Domain)"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-006",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=20.0,
                    evidence=ev,
                    explanation="DGA malware queries many unregistered seed domains before contacting an active C2",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Rule 7: Recently Registered Context (DGA-007)
        # ----------------------------------------------------------------------
        is_recent = features.get("is_recently_registered")
        if is_recent is True:
            age = features.get("domain_age_days")
            ev = f"Recently registered domain ({age} days old <= 30 days)"
            triggered_rules.append(
                RuleEvaluationResult(
                    rule_id="DGA-007",
                    threat_type=DetectionType.DGA,
                    triggered=True,
                    weight=15.0,
                    evidence=ev,
                    explanation="Malicious infrastructure is predominantly hosted on newly registered domains",
                )
            )
            evidence_list.append(ev)

        # ----------------------------------------------------------------------
        # Scoring & Corroboration Logic
        # ----------------------------------------------------------------------
        rule_score = sum(r.weight for r in triggered_rules)

        # Blend ML anomaly input if provided
        if ml_anomaly_score is not None:
            # 70% rule weight + 30% ML anomaly weight
            combined_score = round(min(100.0, (rule_score * 0.70) + (ml_anomaly_score * 0.30)), 2)
            if ml_anomaly_score >= 50.0:
                evidence_list.append(f"ML Anomaly score elevated ({ml_anomaly_score:.1f}/100)")
        else:
            combined_score = round(min(100.0, rule_score), 2)

        indicator_count = len(triggered_rules)
        # Require at least 2 distinct lexical indicators to suppress false positives on short/CDN domains
        is_suspicious = (indicator_count >= 2 and combined_score >= self.config.suspicious_score_cutoff)

        if is_suspicious:
            confidence = round(min(0.98, 0.45 + (indicator_count * 0.12)), 2)
            narrative = f"Possible DGA domain: Corroboration of {indicator_count} lexical signals ({', '.join(evidence_list[:3])})."
        elif indicator_count == 1:
            confidence = 0.25
            narrative = f"Benign/Inconclusive: Single lexical anomaly ({evidence_list[0]}), insufficient for DGA classification."
        else:
            confidence = 0.92
            narrative = "Benign: Lexical and phonological structure matches standard natural domain patterns."

        return DetectorVerdict(
            threat_type=DetectionType.DGA,
            is_suspicious=is_suspicious,
            score=combined_score,
            confidence=confidence,
            evidence=evidence_list,
            reason=narrative,
            model_or_rule="RuleEngine:DGA_Lexical_v1",
            details={
                "triggered_rules": [r.rule_id for r in triggered_rules],
                "indicator_count": indicator_count,
                "entropy": entropy,
                "vowel_ratio": vowel_ratio,
                "consonant_run": consonant_run,
                "ml_anomaly_score": ml_anomaly_score,
            },
        )
