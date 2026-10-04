"""
Integration tests for FastAPI health and diagnostic endpoints.
"""

from fastapi.testclient import TestClient


def test_root_endpoint(api_client: TestClient):
    """Test root info response."""
    response = api_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["framework"] == "DNSGuard"
    assert "version" in data
    assert "docs_url" in data


def test_health_check_endpoint(api_client: TestClient):
    """Test health check endpoint reporting DB and runtime status."""
    response = api_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["app_name"] == "DNSGuard"
    assert "database" in data


def test_system_status_diagnostic(api_client: TestClient):
    """Test system status endpoint providing telemetry and active configuration."""
    response = api_client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "DNSGuard"
    assert data["database_status"] == "connected"
    assert "detection_thresholds" in data
    assert "risk_weights" in data
    assert isinstance(data["audit_chain_valid"], bool)


def test_audit_verification_endpoint(api_client: TestClient):
    """Test audit verification API endpoint."""
    response = api_client.get("/api/v1/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert data["total_records"] >= 1
