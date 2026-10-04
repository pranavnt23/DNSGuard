# DNSGuard: Intelligent DNS Security Monitoring & Threat Detection Framework

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-FastAPI%20%7C%20Streamlit-brightgreen.svg)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20WAL-orange.svg)](https://sqlite.org/)
[![License](https://img.shields.io/badge/License-Academic%20Evaluation-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/Tests-17%20Passed-success.svg)]()

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
- **Privacy-Preserving Logging**: Client IP addresses are pseudonymized using keyed **HMAC-SHA256** prior to database storage, with optional **AES-256-GCM** encryption for raw audit records.
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
                    |       DNS Collector       |  (Scapy / Raw Sockets)
                    +---------------------------+
                                  │
                                  ▼
                    +---------------------------+
                    |        DNS Parser         |  (dnspython / Scapy Dissector)
                    +---------------------------+
                                  │
                                  ▼
                    +---------------------------+
                    |    Feature Extraction     |  (Entropy, N-grams, Length, TTL)
                    +---------------------------+
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          +-------------------+       +--------------------+
          | Rule-Based Engine |       | ML / Anomaly Model |
          | (Tunneling / DGA) |       | (Outlier Profiling)|
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
                    |  Cryptographic Security   |  (HMAC IP Pseudonymisation,
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

## 5. Technology Stack

- **Primary Language**: Python 3.10+
- **Packet Dissection & Networking**: Scapy 2.8+, dnspython 2.8+
- **Data Science & ML**: Pandas, NumPy, Scikit-learn
- **API & Server**: FastAPI, Uvicorn
- **Dashboard & Visualizations**: Streamlit, Plotly
- **Storage**: SQLite 3 (WAL mode enabled, foreign keys enforced)
- **Security & Cryptography**: PyCryptodome (AES-256-GCM), hashlib, hmac (standard library)
- **Testing & Verification**: pytest, httpx

> **Architectural Decision Note**:  
> PostgreSQL, Redis, Docker, React, and Kubernetes were intentionally omitted. SQLite with Write-Ahead Logging (WAL) and memory-efficient Python structures deliver zero-config portability, zero installation friction on lab evaluation machines, and immediate viva inspectability.

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
├── dns_engine/               # Member 1: Packet capture & parsing
│   └── __init__.py           # Submodules: collector, parser, features
├── detection/                # Member 1: Threat detection algorithms
│   └── __init__.py           # Submodules: dga, tunneling, spoofing, ml
├── security/                 # Member 2: Cryptography & Risk Scoring
│   └── __init__.py           # Submodules: crypto, risk, alerts
├── database/                 # Member 2: Persistence & Data Access
│   ├── __init__.py
│   ├── connection.py         # SQLite connection manager (WAL, PRAGMA)
│   ├── models.py             # Domain models, Enums, and schemas
│   ├── repository.py         # CRUD operations and hash chain verifier
│   └── schema.sql            # DDL schema script
├── dashboard/                # Member 2: UI & Analytics
│   └── __init__.py           # Streamlit app and Plotly visual components
├── data/                     # Local storage (SQLite DB, captures, logs)
│   ├── .gitkeep
│   └── dnsguard.db
├── docs/                     # Documentation and viva preparation
│   ├── ARCHITECTURE.md       # Full architectural specification
│   └── VIVA_CHEATSHEET.md    # Viva exam guide and defense cheat sheet
├── tests/                    # Automated test suite (pytest)
│   ├── __init__.py
│   ├── conftest.py           # Test fixtures (isolated DB, sample data)
│   ├── test_config.py        # Settings and validation tests
│   ├── test_database.py      # Database CRUD & tamper-detection tests
│   └── test_health_api.py    # FastAPI endpoint integration tests
├── .env.example              # Environment variables template
├── .gitignore                # Git exclusions
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Pinned project dependencies
└── README.md                 # Project documentation
```

---

## 7. Database Foundation

The SQLite database comprises 4 purpose-built tables configured with foreign keys and index optimization:

1. **`dns_events`**: Stores raw and enriched DNS metadata, query types, response codes, TTLs, and serialized feature dictionaries.
2. **`detection_results`**: Stores detector outputs (DGA, Tunneling, Spoofing, Anomaly), confidence scores, and plain-language reasoning.
3. **`alerts`**: Aggregated security incidents triaged by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with mitigation tracking.
4. **`audit_logs`**: Tamper-evident ledger linking records via:
   $$\text{entry\_hash} = \text{SHA-256}(\text{timestamp} \parallel \text{event\_type} \parallel \text{component} \parallel \text{details} \parallel \text{previous\_hash})$$

---

## 8. Installation & Setup Instructions

### Prerequisites
- Python 3.10 or higher
- Git

### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/pranavnt23/DNSGuard.git
cd DNSGuard

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Activate virtual environment (Linux/macOS)
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
```bash
# Copy template configuration
cp .env.example .env
```
*(Optional)*: Review `.env` to customize capture ports, detection thresholds, or encryption keys.

### Step 4: Initialize Database
```bash
python -c "from database.connection import initialize_database; initialize_database()"
```

### Step 5: Run Automated Tests
```bash
pytest
```
Expected output: **17 passed**.

### Step 6: Start FastAPI Diagnostic Service
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to:
- Interactive API Docs: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/api/v1/health`
- Diagnostic Telemetry: `http://127.0.0.1:8000/api/v1/status`
- Audit Integrity Verification: `http://127.0.0.1:8000/api/v1/audit/verify`

---

## 9. Planned Detection Capabilities (Roadmap)

- **Prompt 2 (DNS Engine & Feature Extraction)**: Live packet capture with Scapy, offline PCAP replay, DNS header/resource record dissection, and feature extraction (Shannon entropy, vowel/digit ratios, n-gram frequency, query rate metrics).
- **Prompt 3 (Detection Engine)**: Implementation of heuristic & ML detectors for DGA domains, DNS tunneling exfiltration patterns, and DNS spoofing/cache poisoning markers.
- **Prompt 4 (Security, Cryptography & Risk Scoring)**: HMAC-SHA256 IP pseudonymisation, AES-256 payload encryption, tamper-evident hash chaining, and multi-factor explainable risk scoring.
- **Prompt 5 (FastAPI & Streamlit Dashboard)**: Interactive multi-page SOC dashboard featuring live traffic visualizer, alert management triage board, threat breakdown charts, and audit chain verification viewer.
- **Prompt 6 (Evaluation & Polish)**: Synthetic attack dataset generation, benchmark evaluation (Precision, Recall, ROC-AUC), project verification, and final viva review.
