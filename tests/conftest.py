"""
Pytest fixtures and test environment configuration for DNSGuard.
"""

import os
import tempfile
from typing import Generator
import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import app
from database.connection import initialize_database
from database.repository import DNSRepository
from database.models import (
    DNSEvent,
    DetectionResult,
    SecurityAlert,
    AlertSeverity,
    AlertStatus,
    DetectionStatus,
    DetectionType,
    current_utc_iso,
)


@pytest.fixture
def temp_db() -> Generator[str, None, None]:
    """
    Creates an isolated temporary SQLite database for test execution.
    Cleans up after the test finishes.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_path = tf.name

    try:
        initialize_database(db_path=temp_path)
        yield temp_path
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@pytest.fixture
def repo(temp_db: str) -> DNSRepository:
    """Provides a repository bound to the isolated temporary test database."""
    return DNSRepository(db_path=temp_db)


@pytest.fixture
def sample_dns_event() -> DNSEvent:
    """Sample DNS event with populated metadata and feature payload."""
    return DNSEvent(
        timestamp=current_utc_iso(),
        client_identifier="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        raw_client_ip="192.168.1.105",
        queried_domain="vbnmkjhgfdsa.malicious-c2.cc",
        query_type="A",
        response_code="NOERROR",
        response_data=["198.51.100.42"],
        ttl=60,
        packet_length=78,
        protocol="UDP",
        source_port=49152,
        destination_port=53,
        extracted_features={
            "entropy": 4.15,
            "domain_length": 28,
            "vowel_ratio": 0.12,
            "has_hex_or_base32": False,
        },
        detection_status=DetectionStatus.PENDING,
    )


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    """Sample detection verdict produced by DGA detector."""
    return DetectionResult(
        dns_event_id=1,
        detection_type=DetectionType.DGA,
        score=88.5,
        confidence=0.92,
        is_suspicious=True,
        reason="Abnormally high Shannon entropy (4.15) and low vowel ratio (0.12)",
        model_or_rule="DGAEntropyRule_v1",
        details={"shannon_entropy": 4.15, "threshold": 3.8},
        timestamp=current_utc_iso(),
    )


@pytest.fixture
def sample_alert() -> SecurityAlert:
    """Sample security alert for triage testing."""
    return SecurityAlert(
        dns_event_id=None,
        domain="vbnmkjhgfdsa.malicious-c2.cc",
        client_identifier="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        threat_type="DGA Domain Activity",
        severity=AlertSeverity.HIGH,
        risk_score=88.5,
        explanation="Detected high probability algorithmically generated domain communicating with command and control.",
        status=AlertStatus.NEW,
        mitigated=False,
    )


@pytest.fixture
def api_client() -> Generator[TestClient, None, None]:
    """TestClient instance for testing FastAPI routes."""
    with TestClient(app) as client:
        yield client
