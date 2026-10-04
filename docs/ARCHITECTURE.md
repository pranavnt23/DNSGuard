# DNSGuard Architecture & System Design Document

## 1. System Overview

DNSGuard is a lightweight, explainable, and demonstrable DNS security monitoring framework designed for an Information Security CAT project. Its architecture follows a unidirectional pipeline where raw DNS transactions are captured, parsed, enriched with statistical features, evaluated against rule-based and machine-learning detectors, assigned an explainable risk score, and persisted with cryptographic integrity.

---

## 2. Component Pipeline

```text
+----------------------------------------------------------------------------------+
|                            PHASE 1: INGESTION (Member 1)                         |
|                                                                                  |
|  [ Live Interface (Scapy) ] OR [ Offline PCAP File ]                             |
|                           │                                                      |
|                           ▼                                                      |
|                 [ DNS Packet Dissection ]                                        |
|         Extract: ID, QR, Opcode, QNAME, QTYPE, RCODE, TTL, Answers               |
+----------------------------------------------------------------------------------+
                                    │
                                    ▼
+----------------------------------------------------------------------------------+
|                       PHASE 2: FEATURE EXTRACTION (Member 1)                     |
|                                                                                  |
|  • Lexical: Shannon Entropy, Vowel Ratio, Digit Ratio, Length, Consonants        |
|  • Structural: Subdomain Depth, TLD Type, RR Type Frequency, Payload Size        |
|  • Behavioral: Inter-arrival Time, Query Velocity, TTL Jitter                    |
+----------------------------------------------------------------------------------+
                                    │
                                    ▼
+----------------------------------------------------------------------------------+
|                       PHASE 3: THREAT DETECTION (Member 1)                       |
|                                                                                  |
|  ┌─────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐ |
|  | DGA Detection       |   | DNS Tunneling Detector|   | DNS Spoofing Detector | |
|  | • Lexical Heuristics|   | • TXT/NULL Payload Len|   | • Cache Poisoning     | |
|  | • N-gram Bigram/Tri |   | • Hex/Base32 Encodings|   | • Unexpected TTL Drops| |
|  | • Random Forest     |   | • Query Burst Rates   |   | • Authority Discrepancy|
|  └─────────────────────┘   └───────────────────────┘   └───────────────────────┘ |
+----------------------------------------------------------------------------------+
                                    │
                                    ▼
+----------------------------------------------------------------------------------+
|                 PHASE 4: RISK SCORING & CLASSIFICATION (Member 2)                |
|                                                                                  |
|  Combined Score = (W_rule * Score_rule) + (W_ml * Score_ml) + (W_ano * Score_ano)|
|                                                                                  |
|  Threshold Cutoffs:                                                              |
|  [0 - 29]: Clean/Low   [30 - 54]: Medium   [55 - 74]: High   [75 - 100]: Critical|
+----------------------------------------------------------------------------------+
                                    │
                                    ▼
+----------------------------------------------------------------------------------+
|              PHASE 5: CRYPTOGRAPHY & SECURE PERSISTENCE (Member 2)               |
|                                                                                  |
|  • HMAC-SHA256 IP Pseudonymisation (Protects Client Privacy)                     |
|  • AES-256-GCM Sensitive Payload / Raw IP Encryption                             |
|  • SHA-256 Chained Tamper-Evident Audit Logging                                  |
|  • SQLite 3 WAL (Write-Ahead Logging) Store                                      |
+----------------------------------------------------------------------------------+
                                    │
                                    ▼
+----------------------------------------------------------------------------------+
|                    PHASE 6: PRESENTATION & TRIAGE (Member 2)                     |
|                                                                                  |
|  • FastAPI REST Endpoints (JSON Data Exchange, Health, Integrations)             |
|  • Streamlit Interactive Web Application (Live Monitor, Alert Queue, KPIs)       |
|  • Plotly Dynamic Visualizations (Threat Distribution, Latency, Volume)          |
+----------------------------------------------------------------------------------+
```

---

## 3. Cryptographic Design (Member 2)

### 3.1 Client IP Pseudonymisation (HMAC-SHA256)
- **Problem**: Plaintext storage of client IPs violates internal privacy norms (GDPR / ISO 27001). Standard hashing (MD5 or raw SHA-256) is vulnerable to offline dictionary rainbow table attacks across private IP spaces (`192.168.0.0/16`, `10.0.0.0/8`).
- **Solution**: A keyed Hash-based Message Authentication Code:
  $$\text{Client\_ID} = \text{HMAC-SHA256}(K_{\text{salt}}, \text{Client\_IP})[:32]$$
- **Properties**: Deterministic per deployment session (allowing correlation of repeated queries from the same compromised endpoint) without exposing the real subnet topology to database readers.

### 3.2 Confidential Data Encryption (AES-256-GCM)
- Optional storage of the real client IP or raw suspicious query payload is encrypted with authenticated symmetric encryption:
  - Key size: 256 bits (32 bytes).
  - Mode: Galois/Counter Mode (GCM).
  - Provides both confidentiality and ciphertext integrity authentication.

### 3.3 Tamper-Evident Audit Hash Chaining (SHA-256)
- Each security audit event is chained to its direct predecessor:
  $$\text{entry\_hash}_i = \text{SHA-256}(\text{timestamp}_i \parallel \text{event\_type}_i \parallel \text{component}_i \parallel \text{details}_i \parallel \text{previous\_hash}_i)$$
- Where $\text{previous\_hash}_i = \text{entry\_hash}_{i-1}$.
- **Tamper Detection**: If an attacker modifies or deletes row $k$, $\text{entry\_hash}_k$ no longer matches its contents, and row $k+1$'s $\text{previous\_hash}$ fails verification.

---

## 4. SQLite Storage & Performance Optimizations

1. **Write-Ahead Logging (WAL)**:
   - `PRAGMA journal_mode = WAL;`
   - Allows concurrent readers while a single writer operates, avoiding database locks during continuous packet capture.
2. **Synchronous Mode**:
   - `PRAGMA synchronous = NORMAL;`
   - Sufficient for prototype durability while maximizing I/O throughput.
3. **Foreign Key Integrity**:
   - `PRAGMA foreign_keys = ON;`
   - Cascades event deletions to detection results and handles alert references cleanly.
