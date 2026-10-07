"""
Data Access Repository for DNSGuard.
Provides strongly-typed CRUD operations and cryptographic audit chain verification.
"""

import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from database.connection import get_db_connection
from database.models import (
    DNSEvent,
    DetectionResult,
    SecurityAlert,
    AuditLogEntry,
    AlertSeverity,
    AlertStatus,
    DetectionStatus,
    DetectionType,
    AuditEventType,
    current_utc_iso,
)
from backend.logging_config import get_logger

logger = get_logger("repository")


class DNSRepository:
    """
    Unified SQLite repository for events, detections, alerts, and audit records.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    # ==========================================================================
    # DNS Event Operations
    # ==========================================================================

    def insert_dns_event(self, event: DNSEvent) -> int:
        """Inserts a new DNS event and returns the newly generated primary key."""
        sql = """
        INSERT INTO dns_events (
            timestamp, client_identifier, raw_client_ip, queried_domain,
            query_type, response_code, response_data, ttl, packet_length,
            protocol, source_port, destination_port, extracted_features,
            detection_status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        response_json = json.dumps(event.response_data or [])
        features_json = json.dumps(event.extracted_features or {})

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    event.timestamp,
                    event.client_identifier,
                    event.raw_client_ip,
                    event.queried_domain,
                    event.query_type,
                    event.response_code,
                    response_json,
                    event.ttl,
                    event.packet_length,
                    event.protocol,
                    event.source_port,
                    event.destination_port,
                    features_json,
                    event.detection_status.value if isinstance(event.detection_status, DetectionStatus) else str(event.detection_status),
                    event.created_at,
                ),
            )
            event_id = cursor.lastrowid
            return int(event_id)

    def get_dns_event(self, event_id: int) -> Optional[DNSEvent]:
        """Retrieves a single DNS event by ID."""
        sql = "SELECT * FROM dns_events WHERE id = ?;"
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (event_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_dns_event(row)

    def list_dns_events(
        self,
        limit: int = 100,
        offset: int = 0,
        domain_filter: Optional[str] = None,
        client_filter: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> List[DNSEvent]:
        """Lists DNS events with optional domain, client, and status filters."""
        query = "SELECT * FROM dns_events WHERE 1=1"
        params: List[Any] = []

        if domain_filter:
            query += " AND queried_domain LIKE ?"
            params.append(f"%{domain_filter}%")
        if client_filter:
            query += " AND client_identifier = ?"
            params.append(client_filter)
        if status_filter:
            query += " AND detection_status = ?"
            params.append(status_filter)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_dns_event(r) for r in rows]

    def update_dns_event_status(self, event_id: int, status: DetectionStatus) -> bool:
        """Updates the analysis status of a DNS event."""
        sql = "UPDATE dns_events SET detection_status = ? WHERE id = ?;"
        status_val = status.value if isinstance(status, DetectionStatus) else str(status)
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (status_val, event_id))
            return cursor.rowcount > 0

    # ==========================================================================
    # Detection Result Operations
    # ==========================================================================

    def insert_detection_result(self, result: DetectionResult) -> int:
        """Inserts an engine detection result."""
        sql = """
        INSERT INTO detection_results (
            dns_event_id, detection_type, score, confidence,
            is_suspicious, reason, model_or_rule, details, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        details_json = json.dumps(result.details or {})
        det_type = result.detection_type.value if hasattr(result.detection_type, "value") else str(result.detection_type)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    result.dns_event_id,
                    det_type,
                    float(result.score),
                    float(result.confidence),
                    1 if result.is_suspicious else 0,
                    result.reason,
                    result.model_or_rule,
                    details_json,
                    result.timestamp,
                ),
            )
            return int(cursor.lastrowid)

    def get_detection_results_for_event(self, dns_event_id: int) -> List[DetectionResult]:
        """Fetches all detector verdicts linked to a particular DNS event."""
        sql = "SELECT * FROM detection_results WHERE dns_event_id = ? ORDER BY id ASC;"
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (dns_event_id,))
            rows = cursor.fetchall()
            return [self._row_to_detection_result(r) for r in rows]

    def list_detection_results(
        self,
        limit: int = 100,
        suspicious_only: bool = False,
        dns_event_id: Optional[int] = None,
    ) -> List[DetectionResult]:
        """Lists recent detection results, optionally filtered to suspicious items or a specific event."""
        clauses = []
        params: List[Any] = []
        if suspicious_only:
            clauses.append("is_suspicious = 1")
        if dns_event_id is not None:
            clauses.append("dns_event_id = ?")
            params.append(dns_event_id)

        sql = "SELECT * FROM detection_results"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            return [self._row_to_detection_result(r) for r in rows]

    # ==========================================================================
    # Alert Operations
    # ==========================================================================

    def insert_alert(self, alert: SecurityAlert) -> int:
        """Inserts a security alert and returns the alert id."""
        sql = """
        INSERT INTO alerts (
            timestamp, dns_event_id, domain, client_identifier,
            threat_type, severity, risk_score, explanation,
            status, mitigated, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        stat = alert.status.value if hasattr(alert.status, "value") else str(alert.status)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    alert.timestamp,
                    alert.dns_event_id,
                    alert.domain,
                    alert.client_identifier,
                    alert.threat_type,
                    sev,
                    float(alert.risk_score),
                    alert.explanation,
                    stat,
                    1 if alert.mitigated else 0,
                    alert.created_at,
                    alert.updated_at,
                ),
            )
            return int(cursor.lastrowid)

    def get_alert(self, alert_id: int) -> Optional[SecurityAlert]:
        """Retrieves a single alert by ID."""
        sql = "SELECT * FROM alerts WHERE id = ?;"
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (alert_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_alert(row)

    def list_alerts(
        self,
        limit: int = 100,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
    ) -> List[SecurityAlert]:
        """Queries alerts by severity or status."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity)
            query += " AND severity = ?"
            params.append(sev_val)
        if status:
            stat_val = status.value if hasattr(status, "value") else str(status)
            query += " AND status = ?"
            params.append(stat_val)

        query += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_alert(r) for r in rows]

    def update_alert_status(
        self,
        alert_id: int,
        status: AlertStatus,
        mitigated: Optional[bool] = None,
    ) -> bool:
        """Updates triage status or mitigation flag for an alert."""
        stat_val = status.value if hasattr(status, "value") else str(status)
        now_ts = current_utc_iso()

        if mitigated is not None:
            sql = "UPDATE alerts SET status = ?, mitigated = ?, updated_at = ? WHERE id = ?;"
            params = [stat_val, 1 if mitigated else 0, now_ts, alert_id]
        else:
            sql = "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?;"
            params = [stat_val, now_ts, alert_id]

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            return cursor.rowcount > 0

    def get_alert_counts_by_severity(self) -> Dict[str, int]:
        """Returns tally of alerts grouped by severity level."""
        sql = "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity;"
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            for row in cursor.fetchall():
                sev = row["severity"]
                if sev in counts:
                    counts[sev] = row["count"]
        return counts

    # ==========================================================================
    # Tamper-Evident Audit Log (SHA-256 Hash Chaining)
    # ==========================================================================

    def insert_audit_log(
        self,
        event_type: AuditEventType,
        user_or_component: str,
        details: str,
        timestamp: Optional[str] = None,
    ) -> AuditLogEntry:
        """
        Appends a new security audit log entry.
        Computes SHA-256(timestamp | event_type | component | details | previous_hash)
        linking each record into a tamper-evident blockchain-like chain.
        """
        ts = timestamp or current_utc_iso()
        etype_str = event_type.value if hasattr(event_type, "value") else str(event_type)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            # Fetch the most recent entry_hash
            cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1;")
            last_row = cursor.fetchone()

            if last_row:
                previous_hash = last_row["entry_hash"]
            else:
                previous_hash = "0" * 64

            # Calculate SHA-256 digest
            payload_to_hash = f"{ts}|{etype_str}|{user_or_component}|{details}|{previous_hash}"
            entry_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()

            sql = """
            INSERT INTO audit_logs (timestamp, event_type, user_or_component, details, previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?);
            """
            cursor.execute(sql, (ts, etype_str, user_or_component, details, previous_hash, entry_hash))
            new_id = cursor.lastrowid

            return AuditLogEntry(
                id=new_id,
                timestamp=ts,
                event_type=event_type,
                user_or_component=user_or_component,
                details=details,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
            )

    def list_audit_logs(self, limit: int = 50) -> List[AuditLogEntry]:
        """Returns the most recent audit logs in reverse chronological order."""
        sql = "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?;"
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (limit,))
            rows = cursor.fetchall()
            return [self._row_to_audit_entry(r) for r in rows]

    def verify_audit_log_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Walks the entire audit log chain in chronological order.
        Verifies that:
        1. Each row's previous_hash matches the prior row's entry_hash.
        2. Each row's entry_hash matches SHA-256(timestamp | event_type | component | details | previous_hash).
        Returns (True, None) if pristine, or (False, error_message) if tampered.
        """
        sql = "SELECT * FROM audit_logs ORDER BY id ASC;"
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()

            if not rows:
                return True, "No audit logs present to verify."

            for i, row in enumerate(rows):
                # Verify recomputed hash matches stored entry_hash
                expected_data = f"{row['timestamp']}|{row['event_type']}|{row['user_or_component']}|{row['details']}|{row['previous_hash']}"
                expected_hash = hashlib.sha256(expected_data.encode("utf-8")).hexdigest()

                if row["entry_hash"] != expected_hash:
                    return (
                        False,
                        f"Integrity violation at log id {row['id']}: entry_hash mismatch. Stored: {row['entry_hash'][:16]}..., Expected: {expected_hash[:16]}...",
                    )

                # Verify hash chain continuity with previous row
                if i > 0:
                    prior_row = rows[i - 1]
                    if row["previous_hash"] != prior_row["entry_hash"]:
                        return (
                            False,
                            f"Hash chain broken at log id {row['id']}: previous_hash does not match prior row entry_hash!",
                        )

            return True, f"Audit log verified: {len(rows)} records are intact with valid SHA-256 hash chaining."

    # ==========================================================================
    # Internal Row Mappers
    # ==========================================================================

    @staticmethod
    def _row_to_dns_event(row: Any) -> DNSEvent:
        response_data = []
        if row["response_data"]:
            try:
                response_data = json.loads(row["response_data"])
            except Exception:
                response_data = [row["response_data"]]

        extracted_features = {}
        if row["extracted_features"]:
            try:
                extracted_features = json.loads(row["extracted_features"])
            except Exception:
                extracted_features = {}

        return DNSEvent(
            id=row["id"],
            timestamp=row["timestamp"],
            client_identifier=row["client_identifier"],
            raw_client_ip=row["raw_client_ip"],
            queried_domain=row["queried_domain"],
            query_type=row["query_type"],
            response_code=row["response_code"],
            response_data=response_data,
            ttl=row["ttl"],
            packet_length=row["packet_length"],
            protocol=row["protocol"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            extracted_features=extracted_features,
            detection_status=DetectionStatus(row["detection_status"]),
            created_at=row["created_at"],
        )

    @staticmethod
    def _row_to_detection_result(row: Any) -> DetectionResult:
        details = {}
        if row["details"]:
            try:
                details = json.loads(row["details"])
            except Exception:
                details = {}

        return DetectionResult(
            id=row["id"],
            dns_event_id=row["dns_event_id"],
            detection_type=DetectionType(row["detection_type"]),
            score=row["score"],
            confidence=row["confidence"],
            is_suspicious=bool(row["is_suspicious"]),
            reason=row["reason"],
            model_or_rule=row["model_or_rule"],
            details=details,
            timestamp=row["timestamp"],
        )

    @staticmethod
    def _row_to_alert(row: Any) -> SecurityAlert:
        return SecurityAlert(
            id=row["id"],
            timestamp=row["timestamp"],
            dns_event_id=row["dns_event_id"],
            domain=row["domain"],
            client_identifier=row["client_identifier"],
            threat_type=row["threat_type"],
            severity=AlertSeverity(row["severity"]),
            risk_score=row["risk_score"],
            explanation=row["explanation"],
            status=AlertStatus(row["status"]),
            mitigated=bool(row["mitigated"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_audit_entry(row: Any) -> AuditLogEntry:
        return AuditLogEntry(
            id=row["id"],
            timestamp=row["timestamp"],
            event_type=AuditEventType(row["event_type"]),
            user_or_component=row["user_or_component"],
            details=row["details"],
            previous_hash=row["previous_hash"],
            entry_hash=row["entry_hash"],
        )
