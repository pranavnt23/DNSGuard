"""
Central Threat Detection Engine for DNSGuard.

Coordinates parallel detector evaluation:
    Extracted Features
           │
           ├──► 1. Machine Learning Anomaly Detector (Isolation Forest)
           ├──► 2. DGA & Suspicious Domain Detector (Lexical + ML)
           ├──► 3. DNS Tunneling & Exfiltration Detector (Multi-signal Rules)
           └──► 4. Spoofing & Cache Poisoning Inconsistency Detector (Historical)
           │
           ▼
    Detection Aggregator
           │
           ▼
    Unified Verdict & SQLite Storage (detection_results)
"""

from typing import Any, Dict, List, Optional
from database.models import DNSEvent, DetectionStatus
from database.repository import DNSRepository
from dns_engine.features import extract_features
from detection.aggregator import DetectionAggregator, UnifiedDetectionVerdict
from detection.anomaly import IsolationForestDetector
from detection.dga import DGADetector
from detection.rules import DetectionConfig, DetectorVerdict
from detection.spoofing import DNSSpoofingDetector, ResponseConsistencyTracker, get_consistency_tracker
from detection.tunneling import DNSTunnelingDetector
from backend.logging_config import get_logger

logger = get_logger("detection_engine")


class ThreatDetectionEngine:
    """
    Central orchestrator executing rule-based and ML threat detectors on DNS transactions.
    """

    def __init__(
        self,
        config: Optional[DetectionConfig] = None,
        repository: Optional[DNSRepository] = None,
        consistency_tracker: Optional[ResponseConsistencyTracker] = None,
        anomaly_detector: Optional[IsolationForestDetector] = None,
    ):
        self.config = config or DetectionConfig()
        self.repo = repository or DNSRepository()
        self.consistency_tracker = consistency_tracker or get_consistency_tracker()

        # Initialize detector submodules
        self.tunneling_detector = DNSTunnelingDetector(config=self.config)
        self.dga_detector = DGADetector(config=self.config)
        self.spoofing_detector = DNSSpoofingDetector(config=self.config, tracker=self.consistency_tracker)
        self.anomaly_detector = anomaly_detector or IsolationForestDetector(config=self.config)

    def analyze_features(
        self,
        features: Dict[str, Any],
        domain: str,
        client_id: str = "unknown",
        dns_event_id: Optional[int] = None,
    ) -> UnifiedDetectionVerdict:
        """
        Runs all detector modules on an extracted feature dictionary and aggregates verdicts.

        Args:
            features: Dictionary of extracted lexical, structural, and behavioral features.
            domain: Domain name.
            client_id: Host or client identifier.
            dns_event_id: Optional primary key of parent DNS event in SQLite.

        Returns:
            UnifiedDetectionVerdict: Combined assessment.
        """
        # Ensure features dictionary has essential domain context
        feature_dict = dict(features)
        feature_dict["domain"] = domain
        feature_dict["queried_domain"] = domain

        # 1. Run Machine Learning Anomaly Detector
        anomaly_verdict: DetectorVerdict = self.anomaly_detector.evaluate(feature_dict)

        # 2. Run DGA Detector (incorporates anomaly score as an evidentiary signal)
        dga_verdict: DetectorVerdict = self.dga_detector.evaluate(
            features=feature_dict,
            ml_anomaly_score=anomaly_verdict.score if anomaly_verdict.is_suspicious else None,
        )

        # 3. Run DNS Tunneling Detector
        tunneling_verdict: DetectorVerdict = self.tunneling_detector.evaluate(feature_dict)

        # 4. Run Spoofing & Response Consistency Detector
        spoofing_verdict: DetectorVerdict = self.spoofing_detector.evaluate(feature_dict)

        verdicts = [tunneling_verdict, dga_verdict, spoofing_verdict, anomaly_verdict]

        # 5. Aggregate results into unified assessment
        return DetectionAggregator.aggregate(
            domain=domain,
            client_identifier=client_id,
            verdicts=verdicts,
            dns_event_id=dns_event_id,
        )

    def analyze_feature_dict(self, item: Dict[str, Any]) -> UnifiedDetectionVerdict:
        """
        Convenience method to inspect a raw feature dictionary or benchmark sample.
        """
        domain = str(item.get("domain") or item.get("queried_domain") or "")
        client_id = str(item.get("client_ip") or item.get("source_ip") or "unknown")

        # If features haven't been extracted yet, extract them on the fly
        if "shannon_entropy" not in item:
            _, features = extract_features(
                domain=domain,
                query_type=str(item.get("query_type", "A")),
                response_code=str(item.get("response_code", "NOERROR")),
                response_data=item.get("response_data", []),
                ttl=item.get("ttl"),
                packet_length=item.get("packet_length"),
            )
            features["response_data"] = item.get("response_data", [])
            features["destination_ip"] = item.get("destination_ip")
            features["dnssec_status"] = item.get("dnssec_status")
            if "is_recently_registered" in item:
                features["is_recently_registered"] = item["is_recently_registered"]
                features["domain_age_days"] = item.get("domain_age_days")
        else:
            features = dict(item)
            if "destination_ip" not in features and "destination_ip" in item:
                features["destination_ip"] = item["destination_ip"]
            if "dnssec_status" not in features and "dnssec_status" in item:
                features["dnssec_status"] = item["dnssec_status"]

        return self.analyze_features(features=features, domain=domain, client_id=client_id)

    def analyze_event(
        self,
        dns_event: DNSEvent,
        store: bool = True,
    ) -> UnifiedDetectionVerdict:
        """
        Processes a stored DNSEvent, executes all detectors, updates event status in SQLite,
        and persists detection_results rows.

        Args:
            dns_event: Canonical database model instance.
            store: If True, writes detection_results rows and updates status in SQLite.

        Returns:
            UnifiedDetectionVerdict: Assessment report.
        """
        features = dict(dns_event.extracted_features or {})
        if not features or "shannon_entropy" not in features:
            _, extracted = extract_features(
                domain=dns_event.queried_domain,
                query_type=dns_event.query_type,
                response_code=dns_event.response_code,
                response_data=dns_event.response_data,
                ttl=dns_event.ttl,
                packet_length=dns_event.packet_length,
            )
            features.update(extracted)

        if dns_event.response_data:
            features["response_data"] = dns_event.response_data
        if dns_event.ttl is not None:
            features["ttl"] = dns_event.ttl
        features["query_type"] = dns_event.query_type
        features["response_code"] = dns_event.response_code
        verdict = self.analyze_features(
            features=features,
            domain=dns_event.queried_domain,
            client_id=dns_event.client_identifier,
            dns_event_id=dns_event.id,
        )

        if store and dns_event.id:
            # 1. Update event detection status
            new_status = DetectionStatus.SUSPICIOUS if verdict.is_suspicious else DetectionStatus.CLEAN
            self.repo.update_dns_event_status(dns_event.id, new_status)

            # 2. Insert detection_results rows for individual detector verdicts
            db_results = DetectionAggregator.to_database_models(verdict, dns_event_id=dns_event.id)
            for res in db_results:
                self.repo.insert_detection_result(res)

            logger.debug(
                "Event #%d (%s) analyzed -> %s (score: %.1f)",
                dns_event.id,
                dns_event.queried_domain,
                new_status.value,
                verdict.overall_score,
            )

        return verdict

    def analyze_domain(self, domain: str, query_type: str = "A") -> UnifiedDetectionVerdict:
        """
        Ad-hoc domain inspection tool for SOC analysts and CLI users.
        """
        _, features = extract_features(domain=domain, query_type=query_type)
        return self.analyze_features(features=features, domain=domain, client_id="adhoc_analyst")

    def process_pending_events(self, batch_size: int = 100) -> List[UnifiedDetectionVerdict]:
        """
        Fetches all unanalyzed ('PENDING') DNS events from SQLite and executes detection.

        Args:
            batch_size: Maximum events to process in this run.

        Returns:
            List[UnifiedDetectionVerdict]: List of completed verdicts.
        """
        pending_events = self.repo.list_dns_events(limit=batch_size, status_filter="PENDING")
        logger.info("Found %d pending DNS event(s) to analyze", len(pending_events))

        verdicts = []
        for event in pending_events:
            v = self.analyze_event(event, store=True)
            verdicts.append(v)

        return verdicts
