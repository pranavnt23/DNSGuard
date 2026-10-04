# DNSGuard: Intelligent DNS Security Monitoring & Threat Detection Framework

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-FastAPI%20%7C%20Streamlit-brightgreen.svg)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20WAL-orange.svg)](https://sqlite.org/)
[![License](https://img.shields.io/badge/License-Academic%20Evaluation-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/Tests-40%20Passed-success.svg)]()

> **Information Security CAT Laboratory Project**  
> A modular, explainable, and demonstrable framework for monitoring DNS traffic, identifying malicious anomalies (DGA, Tunneling, Spoofing/Cache Poisoning), calculating multi-factor risk scores, and maintaining cryptographically verified audit trails.

---

## 1. Project Overview

The Domain Name System (DNS) is foundational to internet communication but inherently lacks built-in authentication in legacy deployments. Adversaries routinely exploit DNS for:
- Command & Control (C2) through **Domain Generation Algorithms (DGA)**
- Covert data exfiltration via **DNS Tunneling** (encapsulating payloads within queries/TXT records)
- Redirection and Man-in-the-Middle (MitM) through **DNS Spoofing & Cache Poisoning**

**DNSGuard** is an end-to-end security framework designed as a working prototype for college-level demonstration and viva examination. It continuously captures DNS transactions, extracts lexical, structural, and behavioral features, runs parallel rule-based and anomaly detection modules, assigns explainable risk scores, and secures log records using cryptographic primitives (AES-256-GCM, HMAC-SHA256, and SHA-256 tamper-evident hash chaining).

---

## 2. Problem Statement

Enterprise Security Operations Centers (SOCs) face critical challenges in DNS security:
1. **High Query Volume vs. Low Signal-to-Noise**: Distinguishing covert exfiltration or transient DGA queries from benign high-volume web traffic.
2. **Black-Box Alerting**: Traditional IDS tools output opaque alert flags without actionable reasoning or feature breakdowns.
3. **Log Integrity & Privacy Violations**: Storing raw internal client IP addresses in query logs violates data privacy standards, while plain-text logs are vulnerable to insider tampering.

DNSGuard addresses these issues through:
- **Explainable Threat Detection**: Every detection verdict records the specific rule or statistical metric (e.g., Shannon entropy cutoff, N-gram abnormality, payload length).
- **Privacy-Preserving Logging**: Client IP addresses are pseudonymized prior to database storage, preparing for keyed **HMAC-SHA256** pseudonymisation.
- **Tamper-Evident Audit Trails**: System logs are cryptographically linked using a **SHA-256 Hash Chain**, rendering log modification or deletion immediately detectable.

---

## 3. High-Level Architecture & Pipeline

```text
                    +---------------------------+
                    | Live Network / PCAP Trace |
                    +---------------------------+
                                  │
                                  ▼
                    +---------------------------+
                    |       DNS Collector       |  (Scapy / Raw Sockets / PCAP Reader)
                    +---------------------------+
                                  │
                                  ▼
                    +---------------------------+
                    |  DNS Parser & Normalizer  |  (dnspython / Scapy Dissector)
                    +---------------------------+
                                  │
                                  ▼
                    +---------------------------+
                    |    Feature Extraction     |  (Entropy, N-grams, Length, TTL, Velocity)
                    +---------------------------+
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          +-------------------+       +--------------------+
          | Rule-Based Engine |       | ML / Anomaly Model |
          | (Prompt 3 Engine) |       | (Prompt 3 Model)   |
          +-------------------+       +--------------------+
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    +---------------------------+
                    |    Explainable Risk       |  (Weighted Score: 0 - 100)
                    |     Scoring Engine        |  (Low / Medium / High / Critical)
                    +---------------------------+
                                  │
                                  ▼
                    +---------------------------+
                    |  Cryptographic Security   |  (IP Pseudonymisation,
                    |     & Persistence         |   AES-256, SHA-256 Hash Chain)
                    +---------------------------+
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          +-------------------+       +--------------------+
          |    FastAPI REST   |       | Streamlit + Plotly |
          |   Service Layer   |       | Analyst Dashboard  |
          +-------------------+       +--------------------+
```

---

## 4. Two-Member Responsibility Division

To facilitate clear academic assessment and viva presentation, the codebase and responsibilities are partitioned between two team members:

| Domain | Member 1: Threat Detection & Engine | Member 2: Security, Platform & Monitoring |
|---|---|---|
| **Core Focus** | Traffic collection, feature extraction, detection algorithms, ML | Cryptography, risk scoring, persistence, API, visualization |
| **Modules Owned** | `dns_engine/`, `detection/`, PCAP parsing | `security/`, `database/`, `backend/`, `dashboard/` |
| **Deliverables** | • Scapy live sniffer & PCAP reader<br>• Lexical feature extractor (Shannon entropy, vowel/consonant ratios, N-grams)<br>• DNS Tunneling detector (payload size, TXT/NULL analysis)<br>• DGA classifier (lexical & ML-based)<br>• DNS spoofing / cache-poisoning indicators<br>• Model evaluation metrics (Precision, Recall, F1) | • SQLite database design & repository layer<br>• HMAC-SHA256 client IP pseudonymisation<br>• AES-256-GCM confidential payload encryption<br>• SHA-256 tamper-evident audit hash chaining<br>• Multi-factor explainable risk scoring engine<br>• Alert generation & triage pipeline<br>• FastAPI REST API<br>• Streamlit + Plotly real-time SOC dashboard |
| **Viva Talking Points** | Packet parsing mechanics, entropy mathematics, n-gram probability, tunneling payload encoding detection | Cryptographic chain verification, IP pseudonymisation vs anonymisation, explainable risk weighting, SQLite concurrency with WAL mode |

---

## 5. DNS Engine & Feature Extraction Pipeline (Implemented in Prompt 2)

### 5.1 Dual Capture Architecture (Live & Offline)
1. **Live Network Capture** (`dns_engine.collector.DNSCollector`):
   - Sniffs network traffic with Scapy using BPF filter: `udp port 53 or tcp port 53`.
   - Supports configurable timeout and packet count limits.
   - **Fault-Tolerant Fallback**: Probes available interfaces and catches missing driver permissions (e.g. absent Npcap) without crashing the application.
2. **Offline Trace & Sample Ingestion** (Primary Demonstration Mode):
   - Ingests standard `.pcap` / `.pcapng` network trace files.
   - Ingests structured `.json` and `.csv` synthetic events.
   - Guarantees 100% reproducible demonstrations on any lab machine without administrative privileges.

### 5.2 Packet Parsing & Domain Normalization
- Dissects DNS Header (`TXID`, `QR`, `RCODE`, `Opcode`).
- Extracts Question Section (`QNAME`, `QTYPE`: A, AAAA, TXT, MX, CNAME, NS, PTR, SOA).
- Extracts Answer Section (Resource records, resolved IP list, `TTL`).
- Normalizes domains: strips trailing dots, downcases casing, verifies RFC 1035 length constraints (max 253 chars total, max 63 chars per label), and extracts SLD, TLD, and subdomains.

### 5.3 Extracted Feature Taxonomy

| Category | Extracted Features | Security Relevance |
|---|---|---|
| **Lexical** | `domain_length`, `digit_ratio`, `vowel_ratio`, `character_diversity`, `max_consonant_sequence`, `shannon_entropy` | Identifies character randomness and consonant clustering typical of DGA domains. |
| **Structural** | `subdomain_count`, `longest_label_length`, `has_suspicious_long_label` ($\ge 40$), `has_hex_or_base32` | Flags long Base32/Base64/Hex encapsulated exfiltration payloads (DNS tunneling). |
| **Protocol / Behavioral** | `query_type_code` (A=1, TXT=16), `response_code` (NOERROR, NXDOMAIN), `ttl_value`, `response_count`, `packet_size` | Catches TXT abuse in tunneling, NXDOMAIN storms in DGA, and abrupt TTL drops in spoofing. |
| **Sliding-Window Velocity** | `query_rate_per_sec`, `client_queries_in_window`, `domain_queries_in_window`, `repeated_query_count` | Monitors burst request frequency per client over a 60-second window. |
| **Domain Registration Context** | `domain_age_days`, `is_recently_registered` ($< 30$ days) | Identifies newly registered domains without requiring live WHOIS calls. |

#### Shannon Entropy Formula:
$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2(p(x_i))$$
- Normal human-registered domains: $2.2 - 3.2$
- DGA pseudo-random domains: $> 3.8$
*(Note: Used as one indicator in the multi-factor risk model, not standalone proof).*

---

## 6. Directory Structure

```text
DNSGuard/
├── backend/                  # API layer and backend service
│   ├── __init__.py
│   ├── config.py             # Pydantic BaseSettings environment loader
│   ├── logging_config.py     # Structured console & rotating file logging
│   ├── main.py               # FastAPI application entry point
│   └── schemas.py            # Shared Pydantic request/response schemas
├── dns_engine/               # Member 1: Traffic Collection, Parsing & Features
│   ├── __init__.py           # Package exports
│   ├── cli.py                # Demonstration CLI tool
│   ├── collector.py          # Scapy live sniffer & PCAP/JSON/CSV reader
│   ├── domain_context.py     # Domain registration age interface & cache
│   ├── entropy.py            # Shannon entropy calculation & label entropy
│   ├── features.py           # Feature extraction engine & activity tracker
│   ├── normalizer.py         # RFC-compliant domain normalization
│   ├── parser.py             # DNS packet dissector (QNAME, QTYPE, Answers)
│   ├── pipeline.py           # End-to-end ingestion pipeline -> SQLite
│   └── sample_data.py        # Realistic synthetic dataset generator
├── detection/                # Member 1: Threat detection algorithms (Prompt 3)
│   └── __init__.py
├── security/                 # Member 2: Cryptography & Risk Scoring (Prompt 4)
│   └── __init__.py
├── database/                 # Member 2: Persistence & Data Access
│   ├── __init__.py
│   ├── connection.py         # SQLite connection manager (WAL, PRAGMA)
│   ├── models.py             # Domain models, Enums, and schemas
│   ├── repository.py         # CRUD operations and hash chain verifier
│   └── schema.sql            # DDL schema script
├── dashboard/                # Member 2: UI & Analytics (Prompt 5)
│   └── __init__.py
├── data/                     # Local storage (SQLite DB, captures, logs)
│   ├── .gitkeep
│   ├── dnsguard.db
│   ├── sample_dns_traffic.json
│   ├── sample_dns_traffic.csv
│   └── sample_dns_traffic.pcap
├── docs/                     # Documentation and viva preparation
│   ├── ARCHITECTURE.md       # Full architectural specification
│   ├── FEATURE_EXTRACTION.md # Technical specification: feature extraction pipeline
│   └── VIVA_CHEATSHEET.md    # Viva exam guide and defense cheat sheet
├── tests/                    # Automated test suite (pytest: 40 tests)
│   ├── __init__.py
│   ├── conftest.py           # Test fixtures (isolated DB, sample data)
│   ├── test_config.py        # Settings and validation tests
│   ├── test_database.py      # Database CRUD & tamper-detection tests
│   ├── test_entropy.py       # Shannon entropy mathematical tests
│   ├── test_features.py      # Feature extraction & activity tracking tests
│   ├── test_health_api.py    # FastAPI endpoint integration tests
│   ├── test_normalizer.py    # Domain normalization & RFC tests
│   ├── test_parser.py        # Packet parsing & malformed packet tests
│   └── test_pipeline.py      # End-to-end ingestion & SQLite storage tests
├── .env.example              # Environment variables template
├── .gitignore                # Git exclusions
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Pinned project dependencies
└── README.md                 # Project documentation
```

---

## 7. Demonstration CLI Commands

The `dns_engine.cli` provides simple commands for demonstration during evaluation:

### 1. Generate Synthetic Datasets (JSON, CSV, PCAP)
```bash
python -m dns_engine.cli --generate-samples
```
*Output:*
```text
[+] Generating synthetic DNS datasets in './data'...
    [OK] JSON Sample:  data/sample_dns_traffic.json
    [OK] CSV Sample:   data/sample_dns_traffic.csv
    [OK] PCAP Trace:   data/sample_dns_traffic.pcap
[+] Done. All synthetic sample formats are ready for demonstration.
```

### 2. Ingest Sample Records into SQLite
```bash
python -m dns_engine.cli --ingest-sample data/sample_dns_traffic.json
```

### 3. Ingest Binary PCAP Trace into SQLite
```bash
python -m dns_engine.cli --ingest-pcap data/sample_dns_traffic.pcap
```

### 4. Inspect & Extract Features for Any Domain
```bash
python -m dns_engine.cli --inspect aW5mby1leGZpbHRyYXRpb24tcGF5bG9hZA.tunnel.evilcorp.net
```
*Output:*
```text
[+] Extracting lexical, structural, and statistical features for:
    Domain: 'aW5mby1leGZpbHRyYXRpb24tcGF5bG9hZA.tunnel.evilcorp.net'

--- Canonical ExtractedFeatures (Prompt 3 Input) ---
{
  "domain_length": 54,
  "subdomain_count": 2,
  "entropy": 4.569,
  "vowel_ratio": 0.2,
  "digit_ratio": 0.1111,
  "max_consonant_sequence": 12,
  "has_hex_or_base32": false,
  "query_type_code": 1,
  "ttl_value": null,
  "packet_size": 86,
  "response_count": 0,
  "query_rate_per_sec": 0.0
}

--- Key Threat Indicator Signals ---
  * Shannon Entropy:         4.569 (Benchmark: >3.8 often signals DGA)
  * Max Label Entropy:       4.2195
  * Domain Length:           54
  * Longest Label Length:    34 (Benchmark: >=40 signals Tunneling)
  * Has Suspicious Length:   False
  * Resembles Hex/Base32:    False
  * Vowel Ratio:             0.2
  * Max Consonant Run:       12
  * Subdomain Depth:         2
  * Structurally RFC-Valid:  True
```

### 5. View Stored Database Telemetry
```bash
python -m dns_engine.cli --stats
```

### 6. Attempt a Short Live Capture (Environment-Permitted)
```bash
python -m dns_engine.cli --capture --timeout 5 --count 10
```

---

## 8. Installation & Setup Instructions

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Initialize Database
```bash
python -c "from database.connection import initialize_database; initialize_database()"
```

### Step 3: Run Automated Test Suite
```bash
python -m pytest
```
Expected output: **40 passed in ~2s**.

### Step 4: Start FastAPI Backend Service
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Endpoints:
- API Docs: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/api/v1/health`
- Diagnostic Status: `http://127.0.0.1:8000/api/v1/status`
- Audit Integrity: `http://127.0.0.1:8000/api/v1/audit/verify`

---

## 9. Development Roadmap

- [x] **Prompt 1**: Architecture, Project Structure, SQLite Foundation, Shared Schemas, Base Tests.
- [x] **Prompt 2**: DNS Packet Collection (Live + PCAP), Parsing & Normalization, Feature Extraction, Sample Datasets.
- [ ] **Prompt 3**: Threat Detection Engine (DGA Classifier, Tunneling Detector, Spoofing/Poisoning Rules, Model Evaluation).
- [ ] **Prompt 4**: Cryptography & Risk Scoring (HMAC-SHA256 IP pseudonymisation, AES-256 payload encryption, Explainable Risk Engine).
- [ ] **Prompt 5**: Interactive Streamlit Dashboard + Plotly Visualizations & FastAPI Integrations.
- [ ] **Prompt 6**: Evaluation Benchmarks, Synthetic Attack Scenarios, Final Polish & Viva Readiness.
