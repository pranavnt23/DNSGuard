"""
Unit and integration tests for the ThreatDetectionEngine and Aggregation layer in DNSGuard.

Tests:
1. Detection engine orchestration and verdict aggregation.
2. SQLite storage of detection_results and status transition of dns_events.
3. False-positive suppression for standard benign domains.
4. Edge cases: empty domains, malformed domains, missing TTL/response/DNSSEC,
   unknown clients, very short domains, very long domains.
"""

import pytest
from database.connection import initialize_database
from database.models import (
    DNSEvent,
    DetectionStatus,
    DetectionType,
    current_utc_iso,
)
from database.repository import DNSRepository
from detection.aggregator import DetectionAggregator, UnifiedDetectionVerdict
from detection.engine import ThreatDetectionEngine
from detection.rules import DetectionConfig, DetectorVerdict


def test_aggregator_combines_multiple_indicators():
    """Verify aggregator synthesizes multiple detector verdicts and selects primary threat."""
    verdict_dga = DetectorVerdict(
        threat_type=DetectionType.DGA,
        is_suspicious=True,
        score=85.0,
        confidence=0.88,
        evidence=["high_entropy (4.2)", "consonant_clustering"],
        reason="DGA pattern detected",
        model_or_rule="DGARule_v1",
    )
    verdict_anomaly = DetectorVerdict(
        threat_type=DetectionType.ANOMALY_ML,
        is_suspicious=True,
        score=72.0,
        confidence=0.70,
        evidence=["feature_outlier: domain_length"],
        reason="Isolation Forest statistical anomaly",
        model_or_rule="IsolationForest_v1",
    )
    verdict_clean = DetectorVerdict(
        threat_type=DetectionType.TUNNELING,
        is_suspicious=False,
        score=0.0,
        confidence=0.90,
        evidence=[],
        reason="Benign label structure",
        model_or_rule="TunnelingRule_v1",
    )

    unified: UnifiedDetectionVerdict = DetectionAggregator.aggregate(
        domain="xkj982pwla10.biz",
        client_identifier="client-101",
        verdicts=[verdict_dga, verdict_anomaly, verdict_clean],
    )

    assert unified.is_suspicious is True
    assert unified.primary_threat_type == DetectionType.DGA
    assert DetectionType.ANOMALY_ML in unified.secondary_threat_types
    assert unified.overall_score >= 85.0
    assert len(unified.all_evidence) >= 3
    assert "rule_based" in unified.detection_methods
    assert "machine_learning" in unified.detection_methods


def test_aggregator_clean_verdict_when_all_clean():
    """Verify that when all detectors report benign, the aggregated verdict is clean."""
    v1 = DetectorVerdict(threat_type=DetectionType.TUNNELING, is_suspicious=False, score=0.0, confidence=0.95, evidence=[], reason="Benign", model_or_rule="T1")
    v2 = DetectorVerdict(threat_type=DetectionType.DGA, is_suspicious=False, score=0.0, confidence=0.95, evidence=[], reason="Benign", model_or_rule="D1")
    v3 = DetectorVerdict(threat_type=DetectionType.SPOOFING, is_suspicious=False, score=0.0, confidence=0.95, evidence=[], reason="Consistent", model_or_rule="S1")
    v4 = DetectorVerdict(threat_type=DetectionType.ANOMALY_ML, is_suspicious=False, score=15.0, confidence=0.85, evidence=[], reason="Normal", model_or_rule="A1")

    unified = DetectionAggregator.aggregate(
        domain="google.com",
        client_identifier="client-1",
        verdicts=[v1, v2, v3, v4],
    )

    assert unified.is_suspicious is False
    assert unified.primary_threat_type is None
    assert unified.overall_score < 40.0
    assert "normal dns traffic" in unified.explanation.lower()


def test_engine_analyze_and_store_in_database(temp_db):
    """Verify end-to-end engine execution, database insertion into detection_results, and status update."""
    repo = DNSRepository(db_path=temp_db)
    engine = ThreatDetectionEngine(repository=repo)

    # 1. Insert a pending suspicious event (DGA style)
    event = DNSEvent(
        timestamp=current_utc_iso(),
        client_identifier="host-abc-123",
        raw_client_ip="10.0.0.15",
        queried_domain="qzwxecrvtbynumu8912.info",
        query_type="A",
        response_code="NXDOMAIN",
        response_data=[],
        ttl=0,
        packet_length=65,
        protocol="UDP",
        source_port=51234,
        destination_port=53,
        detection_status=DetectionStatus.PENDING,
    )
    event_id = repo.insert_dns_event(event)
    event.id = event_id

    # 2. Analyze the event
    verdict = engine.analyze_event(event, store=True)

    # Verify verdict
    assert verdict.is_suspicious is True
    assert verdict.overall_score >= 50.0

    # 3. Verify database state
    stored_event = repo.get_dns_event(event_id)
    assert stored_event is not None
    assert stored_event.detection_status == DetectionStatus.SUSPICIOUS

    # 4. Verify detection_results rows created
    results = repo.list_detection_results(dns_event_id=event_id)
    assert len(results) >= 1
    dga_or_anom = [r for r in results if r.detection_type in (DetectionType.DGA, DetectionType.ANOMALY_ML)]
    assert len(dga_or_anom) >= 1
    assert any(r.is_suspicious for r in results)


def test_engine_process_pending_events_batch(temp_db):
    """Verify batch processing of unanalyzed pending events in SQLite."""
    repo = DNSRepository(db_path=temp_db)
    engine = ThreatDetectionEngine(repository=repo)

    # Insert two events: one benign, one tunneling
    e1 = DNSEvent(
        timestamp=current_utc_iso(),
        client_identifier="client-normal",
        queried_domain="wikipedia.org",
        query_type="A",
        response_code="NOERROR",
        response_data=["208.80.154.224"],
        ttl=300,
        packet_length=70,
        detection_status=DetectionStatus.PENDING,
    )
    repo.insert_dns_event(e1)

    e2 = DNSEvent(
        timestamp=current_utc_iso(),
        client_identifier="client-exfil",
        queried_domain="exfil-a8f9b2c3d4e5f60718293a4b5c6d7e8f9012.attacker-c2.net",
        query_type="TXT",
        response_code="NOERROR",
        response_data=["ack=ok"],
        ttl=10,
        packet_length=150,
        detection_status=DetectionStatus.PENDING,
    )
    repo.insert_dns_event(e2)

    # Run batch processing
    verdicts = engine.process_pending_events(batch_size=10)
    assert len(verdicts) == 2

    # Verify no more pending events remain
    remaining = repo.list_dns_events(status_filter="PENDING")
    assert len(remaining) == 0


def test_normal_traffic_false_positive_avoidance():
    """Verify that common legitimate websites produce clean verdicts."""
    engine = ThreatDetectionEngine()
    benign_domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "stackoverflow.com",
        "cloudflare.com",
    ]

    for domain in benign_domains:
        verdict = engine.analyze_domain(domain=domain, query_type="A")
        assert verdict.is_suspicious is False, f"False positive triggered on {domain}: {verdict.explanation}"
        assert verdict.overall_score < 40.0


# =========================================================================
# EDGE CASE TESTING (Section 14 of Requirements)
# =========================================================================

def test_edge_case_empty_domain():
    """Engine must gracefully handle empty domain without crashing."""
    engine = ThreatDetectionEngine()
    verdict = engine.analyze_features(features={}, domain="", client_id="test")
    assert isinstance(verdict, UnifiedDetectionVerdict)
    assert verdict.is_suspicious is False


def test_edge_case_malformed_domain():
    """Engine must gracefully handle malformed domain names with consecutive dots and symbols."""
    engine = ThreatDetectionEngine()
    malformed = "..invalid..domain---structure..com.."
    verdict = engine.analyze_domain(domain=malformed)
    assert isinstance(verdict, UnifiedDetectionVerdict)
    # Does not crash, handles tokens safely
    assert verdict.domain == malformed


def test_edge_case_missing_ttl():
    """Engine and spoofing detector must gracefully handle missing (None) TTL."""
    engine = ThreatDetectionEngine()
    features = {
        "domain": "test-host.org",
        "ttl": None,
        "response_data": ["1.2.3.4"],
    }
    verdict = engine.analyze_features(features=features, domain="test-host.org")
    assert isinstance(verdict, UnifiedDetectionVerdict)


def test_edge_case_missing_response():
    """Engine must handle missing response_data (None or empty list)."""
    engine = ThreatDetectionEngine()
    features = {
        "domain": "test-no-response.org",
        "ttl": 60,
        "response_data": None,
    }
    verdict = engine.analyze_features(features=features, domain="test-no-response.org")
    assert isinstance(verdict, UnifiedDetectionVerdict)


def test_edge_case_missing_dnssec_status():
    """Engine must handle missing DNSSEC status without treating it as invalid."""
    engine = ThreatDetectionEngine()
    features = {
        "domain": "test-dnssec.org",
        "dnssec_status": None,
    }
    verdict = engine.analyze_features(features=features, domain="test-dnssec.org")
    assert isinstance(verdict, UnifiedDetectionVerdict)
    # Spoofing should not flag unknown DNSSEC as an attack
    spoofing_verdict = engine.spoofing_detector.evaluate(features)
    assert not any("DNSSEC" in ev for ev in spoofing_verdict.evidence)


def test_edge_case_unknown_client():
    """Engine handles missing or unknown client identifier."""
    engine = ThreatDetectionEngine()
    verdict = engine.analyze_features(features={}, domain="example.org", client_id="unknown")
    assert verdict.client_identifier == "unknown"


def test_edge_case_very_short_domain():
    """Very short domains (e.g. 2-4 characters) must not cause division by zero or false DGA."""
    engine = ThreatDetectionEngine()
    short_domains = ["a.co", "x.io", "t.co", "g.cn"]
    for d in short_domains:
        verdict = engine.analyze_domain(domain=d)
        assert verdict.is_suspicious is False


def test_edge_case_very_long_domain():
    """Engine must handle extreme domain lengths (> 250 characters) safely."""
    engine = ThreatDetectionEngine()
    very_long = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 50 + ".com"
    verdict = engine.analyze_domain(domain=very_long)
    assert isinstance(verdict, UnifiedDetectionVerdict)
    # Because of extreme length and 63-char labels, it may flag tunneling or anomaly
    assert verdict.overall_score >= 0.0
