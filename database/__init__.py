"""
DNSGuard Database Module.
Foundation for SQLite persistence, thread-safe connections, and data access.
"""

from database.connection import get_db_connection, initialize_database, DatabaseConnection
from database.models import (
    DNSEvent,
    DetectionResult,
    SecurityAlert,
    AuditLogEntry,
    AlertSeverity,
    AlertStatus,
    DetectionStatus,
)
from database.repository import DNSRepository

__all__ = [
    "get_db_connection",
    "initialize_database",
    "DatabaseConnection",
    "DNSEvent",
    "DetectionResult",
    "SecurityAlert",
    "AuditLogEntry",
    "AlertSeverity",
    "AlertStatus",
    "DetectionStatus",
    "DNSRepository",
]
