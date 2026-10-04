"""
Unit tests for database initialization, schema integrity, repository CRUD, and cryptographic audit logs.
"""

import sqlite3
import pytest
from database.connection import check_db_health, get_db_connection
from database.repository import DNSRepository
from database.models import (
    DNSEvent,
    DetectionResult,
    SecurityAlert,
    AlertSeverity,
    AlertStatus,
    DetectionStatus,
    DetectionType,
    AuditEventType,
)


def test_database_initialization_and_health(temp_db: str):
    """Verify that initialize_database creates all required tables and passes health check."""
    health = check_db_health(temp_db)
    assert health["healthy"] is True
    assert health["status"] == "healthy"
    assert "dns_events" in health["tables"]
    assert "detection_results" in health["tables"]
    assert "alerts" in health["tables"]
    assert "audit_logs" in health["tables"]
    # Genesis audit record must be present
    assert health["tables"]["audit_logs"] >= 1


def test_dns_event_insert_and_retrieve(repo: DNSRepository, sample_dns_event: DNSEvent):
    """Test inserting a DNS event and retrieving it by primary key."""
    event_id = repo.insert_dns_event(sample_dns_event)
    assert event_id > 0

    retrieved = repo.get_dns_event(event_id)
    assert retrieved is not None
    assert retrieved.id == event_id
    assert retrieved.queried_domain == sample_dns_event.queried_domain
    assert retrieved.client_identifier == sample_dns_event.client_identifier
    assert retrieved.ttl == sample_dns_event.ttl
    assert retrieved.extracted_features["entropy"] == 4.15
    assert retrieved.detection_status == DetectionStatus.PENDING


def test_list_dns_events_with_filters(repo: DNSRepository, sample_dns_event: DNSEvent):
    """Test listing DNS events with domain and status filters."""
    repo.insert_dns_event(sample_dns_event)

    # Secondary event
    event2 = sample_dns_event.model_copy(update={"queried_domain": "benign-service.org", "detection_status": DetectionStatus.CLEAN})
    repo.insert_dns_event(event2)

    # Filter by domain substring
    results = repo.list_dns_events(domain_filter="malicious")
    assert len(results) == 1
    assert "malicious-c2" in results[0].queried_domain

    # Filter by status
    clean_results = repo.list_dns_events(status_filter="CLEAN")
    assert len(clean_results) == 1
    assert clean_results[0].queried_domain == "benign-service.org"


def test_update_dns_event_status(repo: DNSRepository, sample_dns_event: DNSEvent):
    """Test updating detection status of an event."""
    event_id = repo.insert_dns_event(sample_dns_event)
    success = repo.update_dns_event_status(event_id, DetectionStatus.MALICIOUS)
    assert success is True

    updated = repo.get_dns_event(event_id)
    assert updated.detection_status == DetectionStatus.MALICIOUS


def test_detection_result_crud(repo: DNSRepository, sample_dns_event: DNSEvent, sample_detection_result: DetectionResult):
    """Test inserting detection results linked to a parent DNS event."""
    event_id = repo.insert_dns_event(sample_dns_event)
    result_to_insert = sample_detection_result.model_copy(update={"dns_event_id": event_id})

    det_id = repo.insert_detection_result(result_to_insert)
    assert det_id > 0

    results = repo.get_detection_results_for_event(event_id)
    assert len(results) == 1
    assert results[0].id == det_id
    assert results[0].detection_type == DetectionType.DGA
    assert results[0].score == 88.5
    assert results[0].is_suspicious is True
    assert "entropy" in results[0].reason.lower()


def test_alert_crud_and_severity_counts(repo: DNSRepository, sample_alert: SecurityAlert):
    """Test creating alerts, updating resolution status, and aggregating severity counts."""
    alert_id = repo.insert_alert(sample_alert)
    assert alert_id > 0

    fetched = repo.get_alert(alert_id)
    assert fetched is not None
    assert fetched.severity == AlertSeverity.HIGH
    assert fetched.status == AlertStatus.NEW
    assert fetched.mitigated is False

    # Update alert status
    updated = repo.update_alert_status(alert_id, AlertStatus.RESOLVED, mitigated=True)
    assert updated is True

    refetched = repo.get_alert(alert_id)
    assert refetched.status == AlertStatus.RESOLVED
    assert refetched.mitigated is True

    # Check severity aggregations
    counts = repo.get_alert_counts_by_severity()
    assert counts["HIGH"] >= 1
    assert counts["CRITICAL"] == 0


def test_alert_linked_to_dns_event(repo: DNSRepository, sample_dns_event: DNSEvent, sample_alert: SecurityAlert):
    """Test linking an alert directly to an existing DNS event ID."""
    event_id = repo.insert_dns_event(sample_dns_event)
    linked_alert = sample_alert.model_copy(update={"dns_event_id": event_id})
    alert_id = repo.insert_alert(linked_alert)
    assert alert_id > 0

    fetched = repo.get_alert(alert_id)
    assert fetched is not None
    assert fetched.dns_event_id == event_id


def test_audit_log_hash_chain_and_tamper_detection(repo: DNSRepository, temp_db: str):
    """
    Cryptographic verification test:
    1. Append several audit entries and verify the SHA-256 hash chain is valid.
    2. Simulate malicious SQLite data tampering.
    3. Verify that verify_audit_log_integrity() detects the tampering!
    """
    # Verify initial genesis chain
    valid, msg = repo.verify_audit_log_integrity()
    assert valid is True

    # Insert sequential audit logs
    entry1 = repo.insert_audit_log(
        event_type=AuditEventType.CAPTURE_START,
        user_or_component="dns_sniffer",
        details="Started packet sniffing on interface eth0",
    )
    assert entry1.entry_hash is not None

    entry2 = repo.insert_audit_log(
        event_type=AuditEventType.ALERT_TRIGGERED,
        user_or_component="risk_engine",
        details="Alert #1 generated for domain vbnmkjhgfdsa.malicious-c2.cc",
    )
    assert entry2.previous_hash == entry1.entry_hash

    # Verify that pristine chain passes
    valid, msg = repo.verify_audit_log_integrity()
    assert valid is True
    assert "intact" in msg.lower()

    # Simulate tampering: directly alter details of entry1 without updating its cryptographic hash
    with get_db_connection(temp_db) as conn:
        conn.execute(
            "UPDATE audit_logs SET details = 'TAMPERED: Attacker erased sniffer event' WHERE id = ?;",
            (entry1.id,),
        )

    # Verify that the tamper detector flags the modification immediately!
    tampered_valid, tamper_msg = repo.verify_audit_log_integrity()
    assert tampered_valid is False
    assert "mismatch" in tamper_msg or "violation" in tamper_msg
