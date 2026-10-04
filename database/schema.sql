-- ==============================================================================
-- DNSGuard Database Schema
-- Target: SQLite 3.35+
-- Features: Foreign key enforcement, WAL mode, Index optimization, Cryptographic Hash Chain
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------
-- Table 1: dns_events
-- Raw and enriched DNS queries and responses captured by Member 1 (DNS Engine)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,                         -- ISO-8601 UTC timestamp
    client_identifier TEXT NOT NULL,                 -- HMAC-SHA256 pseudonymized client IP
    raw_client_ip TEXT,                             -- AES-256-GCM encrypted or masked IP
    queried_domain TEXT NOT NULL,                    -- Domain being resolved (e.g., example.com)
    query_type TEXT NOT NULL,                        -- Query record type (A, AAAA, TXT, MX, etc.)
    response_code TEXT,                             -- NOERROR, NXDOMAIN, SERVFAIL, etc.
    response_data TEXT,                             -- JSON list of resolved IPs or CNAMEs
    ttl INTEGER,                                    -- Time to Live (seconds)
    packet_length INTEGER,                          -- DNS payload length in bytes
    protocol TEXT DEFAULT 'UDP',                    -- UDP or TCP
    source_port INTEGER,                            -- Ephemeral client port
    destination_port INTEGER DEFAULT 53,            -- Server port (usually 53)
    extracted_features TEXT,                        -- JSON object containing numerical/lexical features
    detection_status TEXT DEFAULT 'PENDING',        -- PENDING, CLEAN, SUSPICIOUS, MALICIOUS
    created_at TEXT NOT NULL                        -- Row creation timestamp
);

CREATE INDEX IF NOT EXISTS idx_dns_events_domain ON dns_events(queried_domain);
CREATE INDEX IF NOT EXISTS idx_dns_events_client ON dns_events(client_identifier);
CREATE INDEX IF NOT EXISTS idx_dns_events_timestamp ON dns_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_events_status ON dns_events(detection_status);

-- ------------------------------------------------------------------------------
-- Table 2: detection_results
-- Specific threat signals output by Member 1's detection algorithms
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dns_event_id INTEGER NOT NULL,                   -- Associated DNS event
    detection_type TEXT NOT NULL,                   -- DGA, TUNNELING, SPOOFING, ANOMALY, BURST
    score REAL NOT NULL,                            -- Normalized score (0.0 to 100.0)
    confidence REAL NOT NULL,                       -- Model confidence (0.0 to 1.0)
    is_suspicious INTEGER NOT NULL DEFAULT 0,       -- Boolean flag (1=suspicious, 0=benign)
    reason TEXT NOT NULL,                           -- Explainable human-readable explanation
    model_or_rule TEXT NOT NULL,                    -- Detector identifier (e.g., 'EntropyRule_v1')
    details TEXT,                                   -- JSON string with intermediate feature metrics
    timestamp TEXT NOT NULL,                        -- Detection timestamp
    FOREIGN KEY (dns_event_id) REFERENCES dns_events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_detection_results_event_id ON detection_results(dns_event_id);
CREATE INDEX IF NOT EXISTS idx_detection_results_type ON detection_results(detection_type);
CREATE INDEX IF NOT EXISTS idx_detection_results_suspicious ON detection_results(is_suspicious);

-- ------------------------------------------------------------------------------
-- Table 3: alerts
-- Unified security alerts synthesized by Member 2's Risk Engine
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,                         -- Alert trigger timestamp (ISO-8601)
    dns_event_id INTEGER,                           -- Optional link to root DNS event
    domain TEXT NOT NULL,                           -- Affected domain name
    client_identifier TEXT NOT NULL,                 -- Affected pseudonymized client
    threat_type TEXT NOT NULL,                      -- Primary detected threat category
    severity TEXT NOT NULL,                         -- LOW, MEDIUM, HIGH, CRITICAL
    risk_score REAL NOT NULL,                       -- Aggregate risk score (0.0 to 100.0)
    explanation TEXT NOT NULL,                      -- Explainable narrative for SOC analysts
    status TEXT NOT NULL DEFAULT 'NEW',             -- NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    mitigated INTEGER NOT NULL DEFAULT 0,           -- 1 if mitigation rule/block applied, 0 otherwise
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (dns_event_id) REFERENCES dns_events(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);

-- ------------------------------------------------------------------------------
-- Table 4: audit_logs
-- Cryptographically chained tamper-evident security log (Member 2)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,                         -- Action timestamp (ISO-8601 UTC)
    event_type TEXT NOT NULL,                       -- SYSTEM_BOOT, ALERT_TRIGGER, CONFIG_CHANGE, etc.
    user_or_component TEXT NOT NULL,                -- Originating module or user
    details TEXT NOT NULL,                          -- Event details or payload summary
    previous_hash TEXT NOT NULL,                    -- SHA-256 hash of previous row (hash chain)
    entry_hash TEXT NOT NULL                        -- SHA-256(timestamp + event_type + component + details + previous_hash)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
