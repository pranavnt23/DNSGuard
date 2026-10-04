"""
Shared Pydantic schemas for API request and response payloads.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from database.models import AlertSeverity, AlertStatus, DetectionStatus, AuditEventType


class SystemHealthResponse(BaseModel):
    """Health check endpoint status response."""
    status: str = Field(example="healthy")
    database: Dict[str, Any]
    app_name: str
    app_env: str
    version: str


class SystemStatusResponse(BaseModel):
    """Detailed system diagnostic status."""
    app_name: str
    environment: str
    debug: bool
    database_status: str
    event_count: int
    alert_count: int
    critical_alerts: int
    audit_chain_valid: bool
    detection_thresholds: Dict[str, Any]
    risk_weights: Dict[str, float]


class DNSEventCreateRequest(BaseModel):
    """Ingest API schema for raw or captured DNS events."""
    client_ip: str = Field(description="Client IP address to be pseudonymized")
    queried_domain: str = Field(description="Queried fully qualified domain name")
    query_type: str = Field(default="A", description="DNS RR Type (e.g. A, AAAA, TXT)")
    response_code: Optional[str] = Field(default="NOERROR")
    response_data: Optional[List[str]] = Field(default_factory=list)
    ttl: Optional[int] = Field(default=300)
    packet_length: Optional[int] = Field(default=64)
    protocol: str = Field(default="UDP")
    source_port: Optional[int] = Field(default=54321)


class AlertStatusUpdateRequest(BaseModel):
    """Schema for SOC analyst updating an alert status."""
    status: AlertStatus
    mitigated: Optional[bool] = None


class AuditVerificationResponse(BaseModel):
    """Response returned when verifying the SHA-256 audit log hash chain."""
    is_valid: bool
    message: str
    total_records: int
