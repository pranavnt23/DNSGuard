# Technical Specification: Feature Extraction Engine

> **Document Title**: How DNSGuard Converts Raw DNS Traffic into Machine-Learning and Security Features  
> **Module**: `dns_engine/`  
> **Author**: Member 1 (Threat Detection & DNS Engine)  
> **Target Consumer**: Prompt 3 (Rule & Machine Learning Detection Engine)

---

## 1. Pipeline Overview & Data Transformation

DNSGuard converts raw network frames or offline event streams into high-dimensional, explainable feature vectors following a deterministic four-stage pipeline:

```text
Raw Wire Packet (Scapy) / Offline Sample (JSON/CSV)
                       │
                       ▼
             [ 1. Packet Dissection ]
      Extract IP, Ports, Protocol, DNS Header,
      Question (QNAME, QTYPE), Answers (RDATA, TTL)
                       │
                       ▼
            [ 2. Domain Normalization ]
      Strip trailing dots, lowercase normalization,
      RFC 1035 label extraction (SLD, TLD, Subdomains)
                       │
                       ▼
           [ 3. Feature Extraction ]
      • Lexical & Statistical (Entropy, Ratios, Consonants)
      • Structural & Encodings (Label Lengths, Base32/Hex)
      • Behavioral & Temporal (Sliding-window velocity)
      • Contextual (Domain registration age)
                       │
                       ▼
        [ 4. Canonical Feature Vector ]
          • ExtractedFeatures (Pydantic model)
          • Extended dictionary (30+ metrics)
                       │
                       ▼
           [ SQLite Persistence & ML ]
           (dns_events.extracted_features)
```

---

## 2. Feature Taxonomy & Mathematical Formulations

### Category A: Lexical & Statistical Features

| Feature Name | Type | Description | Security & ML Relevance |
|---|---|---|---|
| `domain_length` | Integer | Total character count of normalized domain | Tunneling queries encapsulate data and have elevated lengths (often > 50 chars). |
| `shannon_entropy` | Float | $H(X) = -\sum_{i=1}^{n} p(x_i) \log_2(p(x_i))$ | Quantifies randomness. Normal domains: $2.2 - 3.2$; DGA domains: $> 3.8$. |
| `max_label_entropy` | Float | $\max_{L \in \text{Labels}} H(L)$ | Detects high-entropy subdomain payloads even if SLD looks ordinary (e.g. `payload.legit.com`). |
| `vowel_ratio` | Float | $\frac{\text{Count}(\{a,e,i,o,u\})}{\max(\text{Alphabetic Characters}, 1)}$ | English phonotactics requires vowels; DGA names have sparse vowel ratios ($< 0.15$). |
| `digit_ratio` | Float | $\frac{\text{Count}([0-9])}{\text{domain\_length}}$ | Benign domains rarely exceed 15% digits; DGA/tunneling names often exceed 30%. |
| `character_diversity`| Float | $\frac{\text{Count}(\text{Unique Characters})}{\text{domain\_length}}$ | Higher in pseudo-random strings; lower in structured word concatenations. |
| `max_consonant_sequence`| Integer | Longest run of adjacent consonants without vowels | English rarely exceeds 3–4 adjacent consonants (`"strengths"` = 3). DGA strings like `"zk49wlmpt"` exceed 5–8. |

#### Shannon Entropy Note:
Shannon entropy measures character distribution unpredictability. It is an **informative signal**, not standalone proof of maliciousness. Certain legitimate services (CDNs, AWS internal hosts) naturally display high entropy, while dictionary DGAs exhibit lower entropy. In Prompt 3, entropy is weighted alongside structural and ML metrics.

---

### Category B: Structural & Encoding Features

| Feature Name | Type | Description | Security & ML Relevance |
|---|---|---|---|
| `subdomain_count` | Integer | Number of subdomain labels above the SLD | High depth ($> 3$) is common in covert tunneling tunnels and C2 hierarchies. |
| `longest_label_length`| Integer | Character count of the longest individual label | RFC 1035 caps labels at 63. Tunneling payloads pack maximum data into labels ($40 - 63$ chars). |
| `has_suspicious_long_label` | Boolean | True if $\text{longest\_label\_length} \ge 40$ | Direct rule indicator for DNS tunneling exfiltration. |
| `has_hex_or_base32` | Boolean | True if label matches `^[0-9a-fA-F]{8,}$` or Base32 regex | Identifies Base64/Base32/Hex encoded payloads used by tools like `iodine` or `dnscat2`. |
| `is_structurally_valid` | Boolean | Satisfies RFC 1035 character and length rules | Malformed characters (underscores, non-ASCII) often indicate tunneling or internal leaks. |

---

### Category C: DNS Protocol & Behavioral Features

| Feature Name | Type | Description | Security & ML Relevance |
|---|---|---|---|
| `query_type` | String | DNS RR Type (`A`, `AAAA`, `TXT`, `MX`, `CNAME`) | Tunneling heavily abuses `TXT` records for higher payload capacity (up to 255 bytes). |
| `query_type_code` | Integer | RFC numerical RR type code (`A` = 1, `TXT` = 16) | Standard numerical encoding for Scikit-learn feature matrices. |
| `response_code` | String | DNS return code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`)| DGA malware generates massive `NXDOMAIN` floods looking for active C2 domains. |
| `ttl_value` | Integer | Time-To-Live in seconds | Sudden drops to $< 5$s or erratic variance indicate DNS spoofing or cache poisoning. |
| `response_count` | Integer | Number of answers returned | Fast-flux C2 networks return many rotating IPs; tunneling often returns single ACK strings. |
| `packet_size` | Integer | Wire length in bytes | Abnormally large packets ($> 120$ bytes) signal payload tunneling. |

---

### Category D: Sliding-Window Client Velocity Features

Managed by `ClientActivityTracker` using a 60-second sliding window per client IP:

| Feature Name | Type | Description | Security & ML Relevance |
|---|---|---|---|
| `client_query_rate_per_sec` | Float | Client queries in window / window duration | Detects automated bots, exfiltration scripts, or amplification bursts. |
| `client_queries_in_window` | Integer | Total queries originated by client in window | Highlights aggressive endpoints. |
| `domain_queries_in_window` | Integer | Total requests to this specific domain | Detects C2 beaconing heartbeats. |
| `repeated_query_count` | Integer | Number of times this exact domain was re-queried | Distinguishes transient queries from sustained communication. |

---

### Category E: Contextual Features (Domain Registration Age)

- **Feature**: `domain_age_days` (Integer or `None`).
- **Indicator**: Malicious domains are overwhelmingly registered $< 30$ days prior to use (frequently $< 72$ hours for campaign-specific DGA domains).
- **Interface**: Managed by `DomainContextProvider`. In test/demo mode, `MockDomainContextProvider` provides deterministic ages for standard and synthetic domains without live internet or WHOIS requirements.

---

## 3. Data Contract for Prompt 3 (Detection Engine)

Every ingested event yields two structured artifacts stored in SQLite (`dns_events`):

1. **Canonical Schema (`ExtractedFeatures`)**:
   ```python
   class ExtractedFeatures(BaseModel):
       domain_length: int
       subdomain_count: int
       entropy: float
       vowel_ratio: float
       digit_ratio: float
       max_consonant_sequence: int
       has_hex_or_base32: bool
       query_type_code: int
       ttl_value: Optional[int]
       packet_size: int
       response_count: int
       query_rate_per_sec: float
   ```
2. **Extended Audit Dictionary**: Contains all 30+ lexical, structural, and temporal metrics serialized as JSON in `dns_events.extracted_features`.

In **Prompt 3**, the Detection Engine will ingest these feature vectors directly into:
- `DGAClassifier` (Random Forest + Shannon Entropy heuristic)
- `TunnelingDetector` (Payload length + Base32/Hex + TXT record rules)
- `SpoofingDetector` (TTL jitter + RCODE + Authority discrepancy)
