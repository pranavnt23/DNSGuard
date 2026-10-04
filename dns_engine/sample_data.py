"""
Realistic Synthetic DNS Dataset Generator for DNSGuard.

Produces labeled synthetic DNS records covering:
- Standard benign browsing (popular domains, standard TTLs)
- Legitimate Cloud/CDN queries (long names, hash labels)
- Synthetic DGA domain candidates (high entropy, consonant clustering)
- Synthetic DNS Tunneling candidates (long base64/hex labels, TXT queries)
- Synthetic DNS Spoofing candidates (anomalous low TTLs, erratic resolvers)
- Repeated query bursts (for velocity and frequency tracking)

DISCLAIMER: All synthetic threat entries are generated safely for laboratory
benchmarking, feature verification, and educational demonstrations.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from backend.logging_config import get_logger

logger = get_logger("sample_data")

SYNTHETIC_DATASET: List[Dict[str, Any]] = [
    # --------------------------------------------------------------------------
    # 1. Benign Standard Web Traffic
    # --------------------------------------------------------------------------
    {
        "timestamp": "2026-10-04T10:00:01Z",
        "client_ip": "192.168.1.100",
        "destination_ip": "8.8.8.8",
        "domain": "google.com",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["142.250.190.46"],
        "ttl": 300,
        "packet_length": 65,
        "is_response": True,
        "synthetic_label": "benign_standard",
    },
    {
        "timestamp": "2026-10-04T10:00:03Z",
        "client_ip": "192.168.1.100",
        "destination_ip": "8.8.8.8",
        "domain": "github.com",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["140.82.112.4"],
        "ttl": 60,
        "packet_length": 72,
        "is_response": True,
        "synthetic_label": "benign_standard",
    },
    {
        "timestamp": "2026-10-04T10:00:06Z",
        "client_ip": "192.168.1.101",
        "destination_ip": "1.1.1.1",
        "domain": "wikipedia.org",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["208.80.154.224"],
        "ttl": 3600,
        "packet_length": 75,
        "is_response": True,
        "synthetic_label": "benign_standard",
    },
    {
        "timestamp": "2026-10-04T10:00:08Z",
        "client_ip": "192.168.1.101",
        "destination_ip": "1.1.1.1",
        "domain": "cloudflare.com",
        "query_type": "AAAA",
        "response_code": "NOERROR",
        "response_data": ["2606:4700::6810:85e5", "2606:4700::6810:84e5"],
        "ttl": 300,
        "packet_length": 98,
        "is_response": True,
        "synthetic_label": "benign_standard",
    },
    {
        "timestamp": "2026-10-04T10:00:10Z",
        "client_ip": "192.168.1.102",
        "destination_ip": "8.8.4.4",
        "domain": "mail.google.com",
        "query_type": "MX",
        "response_code": "NOERROR",
        "response_data": ["gmail-smtp-in.l.google.com"],
        "ttl": 300,
        "packet_length": 88,
        "is_response": True,
        "synthetic_label": "benign_standard",
    },

    # --------------------------------------------------------------------------
    # 2. Benign Complex Cloud / CDN / Microservice Traffic
    # --------------------------------------------------------------------------
    {
        "timestamp": "2026-10-04T10:00:12Z",
        "client_ip": "192.168.1.105",
        "destination_ip": "8.8.8.8",
        "domain": "d3v5k9q8w2.cloudfront.net",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["13.32.182.11"],
        "ttl": 60,
        "packet_length": 92,
        "is_response": True,
        "synthetic_label": "benign_cdn_complex",
    },
    {
        "timestamp": "2026-10-04T10:00:14Z",
        "client_ip": "192.168.1.105",
        "destination_ip": "8.8.8.8",
        "domain": "edge-cache-04.us-east-1.aws.internal",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["10.0.14.88"],
        "ttl": 300,
        "packet_length": 105,
        "is_response": True,
        "synthetic_label": "benign_internal_cloud",
    },

    # --------------------------------------------------------------------------
    # 3. Synthetic DGA (Domain Generation Algorithm) Candidates
    # --------------------------------------------------------------------------
    {
        "timestamp": "2026-10-04T10:00:20Z",
        "client_ip": "192.168.1.110",
        "destination_ip": "8.8.8.8",
        "domain": "zk49wlmpt982xv.info",
        "query_type": "A",
        "response_code": "NXDOMAIN",
        "response_data": [],
        "ttl": None,
        "packet_length": 68,
        "is_response": True,
        "synthetic_label": "synthetic_dga_high_entropy",
    },
    {
        "timestamp": "2026-10-04T10:00:22Z",
        "client_ip": "192.168.1.110",
        "destination_ip": "8.8.8.8",
        "domain": "qwxzrtplmnbkdfg.cc",
        "query_type": "A",
        "response_code": "NXDOMAIN",
        "response_data": [],
        "ttl": None,
        "packet_length": 66,
        "is_response": True,
        "synthetic_label": "synthetic_dga_consonants",
    },
    {
        "timestamp": "2026-10-04T10:00:24Z",
        "client_ip": "192.168.1.110",
        "destination_ip": "8.8.8.8",
        "domain": "1a2b3c4d5e6f7g8h.biz",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["198.51.100.22"],
        "ttl": 30,
        "packet_length": 76,
        "is_response": True,
        "synthetic_label": "synthetic_dga_active_c2",
    },
    {
        "timestamp": "2026-10-04T10:00:26Z",
        "client_ip": "192.168.1.110",
        "destination_ip": "8.8.8.8",
        "domain": "jklmnpqrstuvwxyz123.top",
        "query_type": "A",
        "response_code": "NXDOMAIN",
        "response_data": [],
        "ttl": None,
        "packet_length": 74,
        "is_response": True,
        "synthetic_label": "synthetic_dga_alphabetical",
    },

    # --------------------------------------------------------------------------
    # 4. Synthetic DNS Tunneling / Exfiltration Candidates
    # --------------------------------------------------------------------------
    {
        "timestamp": "2026-10-04T10:00:30Z",
        "client_ip": "192.168.1.120",
        "destination_ip": "192.168.1.1",
        "domain": "aW5mby1leGZpbHRyYXRpb24tcGF5bG9hZC1kYXRh.tunnel.c2-exfil.net",
        "query_type": "TXT",
        "response_code": "NOERROR",
        "response_data": ["ACK_CHUNK_001"],
        "ttl": 10,
        "packet_length": 142,
        "is_response": True,
        "synthetic_label": "synthetic_tunneling_base64",
    },
    {
        "timestamp": "2026-10-04T10:00:32Z",
        "client_ip": "192.168.1.120",
        "destination_ip": "192.168.1.1",
        "domain": "66696c652d646174612d657866696c74726174696f6e.exfil.attacker.org",
        "query_type": "TXT",
        "response_code": "NOERROR",
        "response_data": ["RECEIVED_PART_2"],
        "ttl": 5,
        "packet_length": 156,
        "is_response": True,
        "synthetic_label": "synthetic_tunneling_hex",
    },
    {
        "timestamp": "2026-10-04T10:00:34Z",
        "client_ip": "192.168.1.120",
        "destination_ip": "192.168.1.1",
        "domain": "cGFzc3dvcmRzLWFuZC1jcmVkZW50aWFscy1kdW1w.data.tunneling-lab.cc",
        "query_type": "TXT",
        "response_code": "NOERROR",
        "response_data": ["STATUS_OK"],
        "ttl": 10,
        "packet_length": 150,
        "is_response": True,
        "synthetic_label": "synthetic_tunneling_payload",
    },

    # --------------------------------------------------------------------------
    # 5. Synthetic DNS Cache Poisoning / Spoofing Indicators
    # --------------------------------------------------------------------------
    {
        "timestamp": "2026-10-04T10:00:40Z",
        "client_ip": "192.168.1.130",
        "destination_ip": "8.8.8.8",
        "domain": "bank-secure-login.com",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["203.0.113.88"],
        "ttl": 1,  # Suspiciously abrupt TTL drop indicating cache poisoning attempt
        "packet_length": 78,
        "is_response": True,
        "synthetic_label": "synthetic_spoofing_ttl_drop",
    },
    {
        "timestamp": "2026-10-04T10:00:42Z",
        "client_ip": "192.168.1.130",
        "destination_ip": "8.8.8.8",
        "domain": "update-service.windows.net",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["198.51.100.99"],
        "ttl": 3,
        "packet_length": 82,
        "is_response": True,
        "synthetic_label": "synthetic_spoofing_unauthoritative",
    },

    # --------------------------------------------------------------------------
    # 6. High-Frequency Burst Queries (Velocity Testing)
    # --------------------------------------------------------------------------
    {
        "timestamp": "2026-10-04T10:00:50Z",
        "client_ip": "192.168.1.140",
        "destination_ip": "8.8.8.8",
        "domain": "beacon-pulse.telemetry-sync.org",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["192.0.2.1"],
        "ttl": 15,
        "packet_length": 84,
        "is_response": True,
        "synthetic_label": "synthetic_burst_query_1",
    },
    {
        "timestamp": "2026-10-04T10:00:51Z",
        "client_ip": "192.168.1.140",
        "destination_ip": "8.8.8.8",
        "domain": "beacon-pulse.telemetry-sync.org",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["192.0.2.1"],
        "ttl": 15,
        "packet_length": 84,
        "is_response": True,
        "synthetic_label": "synthetic_burst_query_2",
    },
    {
        "timestamp": "2026-10-04T10:00:52Z",
        "client_ip": "192.168.1.140",
        "destination_ip": "8.8.8.8",
        "domain": "beacon-pulse.telemetry-sync.org",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["192.0.2.1"],
        "ttl": 15,
        "packet_length": 84,
        "is_response": True,
        "synthetic_label": "synthetic_burst_query_3",
    },
]


def generate_sample_dataset() -> List[Dict[str, Any]]:
    """Returns a fresh copy of the synthetic benchmark dataset."""
    return [dict(item) for item in SYNTHETIC_DATASET]


def save_sample_dataset_files(data_dir: str = "./data") -> Dict[str, str]:
    """
    Generates and saves the synthetic dataset into JSON, CSV, and PCAP formats.
    Enables zero-configuration offline demonstration and testing.

    Args:
        data_dir: Target directory path.

    Returns:
        Dict[str, str]: Paths to generated files ('json', 'csv', 'pcap').
    """
    target = Path(data_dir)
    target.mkdir(parents=True, exist_ok=True)

    json_path = target / "sample_dns_traffic.json"
    csv_path = target / "sample_dns_traffic.csv"
    pcap_path = target / "sample_dns_traffic.pcap"

    dataset = generate_sample_dataset()

    # 1. Write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)
    logger.info("Generated sample JSON dataset at: %s", json_path)

    # 2. Write CSV
    if dataset:
        fieldnames = list(dataset[0].keys())
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in dataset:
                clean_row = dict(row)
                if isinstance(clean_row.get("response_data"), list):
                    clean_row["response_data"] = ",".join(clean_row["response_data"])
                writer.writerow(clean_row)
        logger.info("Generated sample CSV dataset at: %s", csv_path)

    # 3. Write PCAP using Scapy
    try:
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, UDP
        from scapy.utils import wrpcap

        scapy_packets = []
        for i, item in enumerate(dataset):
            domain = item["domain"]
            qtype = item["query_type"]
            src = item.get("client_ip", "192.168.1.100")
            dst = item.get("destination_ip", "8.8.8.8")
            is_resp = item.get("is_response", False)

            # Query frame
            query_pkt = (
                IP(src=src, dst=dst)
                / UDP(sport=50000 + (i % 1000), dport=53)
                / DNS(id=1000 + i, qr=0, rd=1, qd=DNSQR(qname=f"{domain}.", qtype=qtype))
            )
            scapy_packets.append(query_pkt)

            # Response frame (if marked as response)
            if is_resp:
                rcode = 0 if item.get("response_code") == "NOERROR" else 3
                resp_answers = None
                rdata_list = item.get("response_data", [])

                if rdata_list and qtype == "A":
                    resp_answers = DNSRR(rrname=f"{domain}.", type="A", rdata=rdata_list[0], ttl=item.get("ttl", 300))
                elif rdata_list and qtype == "TXT":
                    resp_answers = DNSRR(rrname=f"{domain}.", type="TXT", rdata=rdata_list[0], ttl=item.get("ttl", 60))

                resp_pkt = (
                    IP(src=dst, dst=src)
                    / UDP(sport=53, dport=50000 + (i % 1000))
                    / DNS(id=1000 + i, qr=1, aa=1, rcode=rcode, qd=DNSQR(qname=f"{domain}.", qtype=qtype), an=resp_answers)
                )
                scapy_packets.append(resp_pkt)

        wrpcap(str(pcap_path), scapy_packets)
        logger.info("Generated synthetic PCAP capture (%d packets) at: %s", len(scapy_packets), pcap_path)

    except Exception as exc:
        logger.warning("Could not synthesize PCAP file (Scapy layer warning): %s", exc)

    return {
        "json": str(json_path),
        "csv": str(csv_path),
        "pcap": str(pcap_path),
    }
