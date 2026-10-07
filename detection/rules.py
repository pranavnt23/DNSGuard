"""
Configurable Rule Engine and Detection Data Contracts for DNSGuard.

Eliminates magic numbers by centralizing detection thresholds, rule definitions,
evidence weights, and detector verdict schemas.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, ConfigDict

from backend.config import get_settings
from database.models import DetectionType


class DetectionConfig(BaseModel):
    """
    Centralized, configurable thresholds for rule-based and ML detection.
    Can be dynamically instantiated or initialized from environment settings.
    """
    # DGA thresholds
    dga_entropy_threshold: float = Field(default=3.8, description="Shannon entropy threshold for DGA detection")
    dga_vowel_ratio_threshold: float = Field(default=0.15, description="Vowel ratio threshold below which name is suspicious")
    dga_consonant_run_threshold: int = Field(default=5, description="Max consecutive consonants threshold")
    dga_digit_ratio_threshold: float = Field(default=0.30, description="Digit ratio threshold")
    dga_diversity_threshold: float = Field(default=0.75, description="Character diversity threshold")

    # DNS Tunneling thresholds
    tunneling_longest_label_threshold: int = Field(default=40, description="Label length threshold for data encapsulation")
    tunneling_domain_length_threshold: int = Field(default=55, description="Total domain length threshold")
    tunneling_max_label_entropy_threshold: float = Field(default=3.9, description="Subdomain label entropy threshold")
    tunneling_subdomain_depth_threshold: int = Field(default=3, description="Subdomain depth threshold")
    tunneling_large_packet_threshold: int = Field(default=120, description="Packet size threshold for exfil frames")

    # Spoofing / Consistency thresholds
    spoofing_ttl_drop_threshold: int = Field(default=5, description="Abnormally low TTL threshold in seconds")
    spoofing_ttl_variance_threshold: int = Field(default=60, description="TTL jitter threshold across same domain")

    # Behavioral / Velocity thresholds
    burst_query_rate_threshold: float = Field(default=20.0, description="Queries per second burst threshold")

    # Classification cutoffs
    suspicious_score_cutoff: float = Field(default=40.0, description="Score threshold to flag an event as suspicious")
    anomaly_contamination: float = Field(default=0.10, description="IsolationForest expected anomaly proportion")

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_settings(cls) -> "DetectionConfig":
        """Creates configuration populated from backend environment settings."""
        settings = get_settings()
        return cls(
            dga_entropy_threshold=settings.dga_entropy_threshold,
            tunneling_longest_label_threshold=settings.tunneling_payload_len_threshold,
            spoofing_ttl_variance_threshold=settings.spoofing_ttl_variance_threshold,
            burst_query_rate_threshold=settings.burst_query_rate_threshold,
        )


class RuleEvaluationResult(BaseModel):
    """Result of evaluating a single detection rule."""
    rule_id: str
    threat_type: DetectionType
    triggered: bool
    weight: float
    evidence: Optional[str] = None
    explanation: str

    model_config = ConfigDict(from_attributes=True)


class DetectorVerdict(BaseModel):
    """
    Standard verdict produced by an individual detector (DGA, Tunneling, Spoofing, or Anomaly).
    Ready for aggregation and downstream risk scoring.
    """
    threat_type: DetectionType
    is_suspicious: bool = False
    score: float = Field(ge=0.0, le=100.0, description="Suspicion score 0 to 100")
    confidence: float = Field(ge=0.0, le=1.0, description="Detector confidence 0.0 to 1.0")
    evidence: List[str] = Field(default_factory=list, description="Structured list of triggered signals")
    reason: str = Field(description="Explainable human-readable justification")
    model_or_rule: str = Field(description="Identifier of model or rule family used")
    details: Dict[str, Any] = Field(default_factory=dict, description="Intermediate metrics and sub-scores")

    model_config = ConfigDict(from_attributes=True)


class RuleDefinition(BaseModel):
    """Metadata and logic for a detection rule."""
    rule_id: str
    threat_type: DetectionType
    name: str
    description: str
    weight: float = Field(ge=1.0, le=50.0, description="Contribution to threat suspicion score")
    evaluator: Callable[[Dict[str, Any], DetectionConfig], Tuple[bool, Optional[str], str]]

    model_config = ConfigDict(arbitrary_types_allowed=True)
