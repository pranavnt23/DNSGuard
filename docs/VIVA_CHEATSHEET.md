# DNSGuard: College CAT Viva Examination Cheat Sheet

This guide is designed for both team members to confidently defend the system architecture, mathematical models, cryptographic decisions, and division of work during the viva evaluation.

---

## 1. Quick Project Elevator Pitch (Both Members)

> *"DNSGuard is an intelligent, explainable DNS threat detection framework. It monitors live or recorded DNS traffic to catch attacks that traditional firewalls miss—specifically DGA domains used by malware botnets, DNS tunneling used for covert data exfiltration, and cache poisoning indicators. It pairs detection with cryptographic security: HMAC-SHA256 for client IP pseudonymisation, AES-256-GCM for sensitive data encryption, and a SHA-256 tamper-evident hash chain for audit logging."*

---

## 2. Member 1 Questions & Answers (Threat Detection & DNS Engine)

### Q1: What is a DGA (Domain Generation Algorithm) and how does DNSGuard detect it?
- **Answer**: DGAs are algorithms used by malware families (like Conficker or GameOver Zeus) to periodically generate dozens or hundreds of pseudo-random domain names to contact Command & Control (C2) servers. Because the domains change daily, static domain blocklists fail.
- **Detection Method**:
  1. **Shannon Entropy**: Measures randomness in the character distribution of the second-level domain (SLD). Natural language domains have entropy around 2.5–3.2, whereas DGA domains frequently exceed 3.8.
  2. **Vowel-to-Consonant Ratio**: DGA domains contain unnatural sequences of consonants (e.g., `xrtqplkm.com`), yielding vowel ratios < 0.15.
  3. **N-gram Likelihood**: Frequency distribution of bigrams/trigrams compared against natural English/dictionary distributions.

### Q2: How does DNS Tunneling work and what features expose it?
- **Answer**: DNS tunneling encodes non-DNS protocols (like SSH or HTTP) or exfiltrated files into DNS query labels (e.g., `<base64-data>.attacker-c2.com`) or TXT/NULL record responses.
- **Key Indicators**:
  1. **Unusual Label Length**: Standard queries are short (< 20 characters); tunneling payloads maximize label lengths up to the 63-character limit per label.
  2. **Character Set Encoding**: High occurrence of hexadecimal characters (`[0-9a-f]`) or Base32/Base64 character sets.
  3. **High TXT Record Volume**: Benign networks query predominantly `A` and `AAAA` records; tunneling tools frequently abuse `TXT` records to bypass egress firewalls.
  4. **Burst Rate**: Sustained high-frequency queries to the same parent domain.

### Q3: How do you detect DNS Spoofing / Cache Poisoning?
- **Answer**:
  1. **Transaction ID (TXID) Predictability**: Evaluating whether the 16-bit query TXID sequences lack entropy or exhibit linear patterns.
  2. **TTL Variance**: Unexpectedly sudden drops or anomalous TTLs from unauthoritative servers.
  3. **Mismatched Authority Answers**: Glue records or NS records returning IPs outside the legitimate authoritative zone.

---

## 3. Member 2 Questions & Answers (Security, Cryptography & Monitoring)

### Q1: Why use HMAC-SHA256 for IP pseudonymisation instead of standard SHA-256?
- **Answer**: The entire IPv4 address space consists of only $2^{32} \approx 4.3 \text{ billion}$ possible addresses. An attacker with a precomputed rainbow table can reverse a plain SHA-256 or MD5 hash of an IP in minutes. By utilizing **HMAC-SHA256** with a secret salt ($K_{\text{salt}}$), precomputation is impossible without knowledge of the server's key, preserving user privacy compliant with data protection norms.

### Q2: How does your Tamper-Evident Audit Log work?
- **Answer**: We implement a **cryptographic hash chain**:
  $$\text{entry\_hash}_i = \text{SHA-256}(\text{timestamp}_i \parallel \text{event\_type}_i \parallel \text{component}_i \parallel \text{details}_i \parallel \text{previous\_hash}_i)$$
  Every new entry incorporates the hash of the preceding entry. If an attacker opens the SQLite database and modifies or deletes a single log record, the hash of that row and all subsequent rows will break. Our `verify_audit_log_integrity()` function walks the chain and flags any tampering with the exact record index.

### Q3: Why did you choose AES-256-GCM?
- **Answer**: GCM (Galois/Counter Mode) provides **Authenticated Encryption with Associated Data (AEAD)**. Unlike older modes like CBC (which requires separate HMAC for integrity and is vulnerable to padding oracle attacks) or ECB (which leaks plaintext patterns), GCM produces a 128-bit authentication tag that guarantees both confidentiality and ciphertext integrity.

### Q4: Why use SQLite instead of PostgreSQL or MySQL for this project?
- **Answer**: SQLite is serverless, zero-configuration, and portable. In SQLite 3 with **WAL mode (Write-Ahead Logging)** enabled, readers do not block writers and writers do not block readers, providing sufficient concurrent throughput for prototype traffic while remaining inspectable with standard tools during a viva.

### Q5: How is the Risk Score calculated?
- **Answer**: Risk is an explainable composite score:
  $$\text{Risk} = (W_{\text{rule}} \times S_{\text{rule}}) + (W_{\text{ml}} \times S_{\text{ml}}) + (W_{\text{anomaly}} \times S_{\text{anomaly}})$$
  Where $W_{\text{rule}} = 0.4$, $W_{\text{ml}} = 0.4$, and $W_{\text{anomaly}} = 0.2$. This ensures that alarms are not triggered by a single noisy heuristic, and provides the SOC analyst with clear mathematical justification for the alert severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
