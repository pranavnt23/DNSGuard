"""
DNS Packet Dissector & Parser module for DNSGuard.

Converts raw Scapy network frames and offline dictionary records into
structured, validated ParsedDNSEvent objects with defensive error handling.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.logging_config import get_logger
from dns_engine.normalizer import normalize_domain

logger = get_logger("parser")

# DNS RCODE to Name mapping (RFC 1035)
RCODE_NAMES: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

# DNS QTYPE to Name mapping (RFC 1035, RFC 3596)
QTYPE_NAMES: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def _current_iso_timestamp() -> str:
    """Returns the current UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


class ParsedDNSEvent(BaseModel):
    """
    Normalized intermediate representation of a DNS query or response.
    Bridges network packet capture and feature extraction.
    """
    timestamp: str = Field(default_factory=_current_iso_timestamp)
    source_ip: str = Field(default="0.0.0.0", description="Originating client IP")
    destination_ip: str = Field(default="0.0.0.0", description="Destination resolver/server IP")
    source_port: int = Field(default=0)
    destination_port: int = Field(default=53)
    protocol: str = Field(default="UDP")
    transaction_id: Optional[int] = Field(default=None, description="16-bit DNS transaction ID (TXID)")
    is_response: bool = Field(default=False, description="True if response (QR=1), False if query (QR=0)")
    queried_domain: str = Field(description="Normalized query domain")
    raw_domain: str = Field(default="", description="Original un-normalized domain string")
    query_type: str = Field(default="A", description="DNS record type (A, AAAA, TXT, etc.)")
    response_code: Optional[str] = Field(default="NOERROR", description="DNS return code (NOERROR, NXDOMAIN, etc.)")
    response_data: List[str] = Field(default_factory=list, description="Resolved addresses or resource strings")
    ttl: Optional[int] = Field(default=None, description="Time to live in seconds")
    packet_length: int = Field(default=0, description="Total packet length in bytes")
    client_identifier: str = Field(default="", description="Privacy-preserving client identity placeholder")

    model_config = ConfigDict(from_attributes=True)


def _decode_bytes_safely(val: Any) -> str:
    """Safely decodes bytes, strings, or numbers into clean text."""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace").strip()
    return str(val).strip()


def parse_scapy_packet(pkt: Any) -> Optional[ParsedDNSEvent]:
    """
    Parses a live or captured Scapy network packet into a normalized ParsedDNSEvent.
    Gracefully handles incomplete, truncated, or malformed packets without raising exceptions.

    Args:
        pkt: Scapy Packet object.

    Returns:
        Optional[ParsedDNSEvent]: Parsed event model, or None if packet is not valid DNS.
    """
    # Defensive check: verify Scapy packet has DNS layer
    if not hasattr(pkt, "haslayer"):
        return None

    # Lazy-import Scapy layers to prevent unnecessary startup overhead
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if not pkt.haslayer(DNS):
        return None

    try:
        dns_layer = pkt[DNS]

        # Extract Network / Transport metadata
        source_ip = "0.0.0.0"
        destination_ip = "0.0.0.0"
        if pkt.haslayer(IP):
            source_ip = pkt[IP].src
            destination_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            source_ip = pkt[IPv6].src
            destination_ip = pkt[IPv6].dst

        source_port = 0
        destination_port = 53
        protocol = "UDP"
        if pkt.haslayer(UDP):
            source_port = pkt[UDP].sport
            destination_port = pkt[UDP].dport
            protocol = "UDP"
        elif pkt.haslayer(TCP):
            source_port = pkt[TCP].sport
            destination_port = pkt[TCP].dport
            protocol = "TCP"

        # Packet timestamp
        pkt_time = getattr(pkt, "time", None)
        if pkt_time:
            timestamp = datetime.fromtimestamp(float(pkt_time), timezone.utc).isoformat()
        else:
            timestamp = _current_iso_timestamp()

        # Wire length
        packet_len = len(pkt)

        # DNS Header fields
        txid = getattr(dns_layer, "id", None)
        qr_flag = getattr(dns_layer, "qr", 0)
        is_response = bool(qr_flag == 1)

        rcode_val = getattr(dns_layer, "rcode", 0)
        response_code = RCODE_NAMES.get(rcode_val, f"RCODE_{rcode_val}")

        # Extract Queried Domain (Question Section)
        raw_qname = ""
        query_type = "A"

        if dns_layer.qd:
            # Handle both single DNSQR and Scapy PacketList of questions
            qd_record = dns_layer.qd
            if hasattr(qd_record, "__getitem__"):
                try:
                    qd_record = qd_record[0]
                except (IndexError, TypeError):
                    pass

            raw_qname_val = getattr(qd_record, "qname", "")
            raw_qname = _decode_bytes_safely(raw_qname_val)
            qtype_val = getattr(qd_record, "qtype", 1)
            query_type = QTYPE_NAMES.get(qtype_val, f"TYPE_{qtype_val}")

        # Normalize domain
        normalized_info = normalize_domain(raw_qname)
        queried_domain = normalized_info.normalized_domain or "unknown"

        # Extract Answers (Answer Section)
        response_data: List[str] = []
        min_ttl: Optional[int] = None

        ancount_val = getattr(dns_layer, "ancount", 0)
        ancount = int(ancount_val) if ancount_val is not None else 0

        if is_response and (ancount > 0 or bool(dns_layer.an)):
            an_layer = dns_layer.an
            records_to_process = []
            if isinstance(an_layer, (list, tuple)) or hasattr(an_layer, "__iter__"):
                records_to_process = list(an_layer)
            else:
                curr = an_layer
                while curr and hasattr(curr, "rdata"):
                    records_to_process.append(curr)
                    curr = getattr(curr, "payload", None)

            for rr in records_to_process:
                # Extract TTL
                rr_ttl = getattr(rr, "ttl", None)
                if rr_ttl is not None:
                    try:
                        int_ttl = int(rr_ttl)
                        if min_ttl is None or int_ttl < min_ttl:
                            min_ttl = int_ttl
                    except (ValueError, TypeError):
                        pass

                # Extract Answer Data
                rdata = getattr(rr, "rdata", None)
                if rdata is not None:
                    if isinstance(rdata, (list, tuple)):
                        for item in rdata:
                            response_data.append(_decode_bytes_safely(item))
                    else:
                        response_data.append(_decode_bytes_safely(rdata))

        # Temporary privacy pseudonym placeholder for Prompt 2 (Member 2 HMAC drops in later)
        client_id_placeholder = f"host_{source_ip.replace('.', '_').replace(':', '_')}"

        return ParsedDNSEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            transaction_id=txid,
            is_response=is_response,
            queried_domain=queried_domain,
            raw_domain=raw_qname,
            query_type=query_type,
            response_code=response_code,
            response_data=response_data,
            ttl=min_ttl,
            packet_length=packet_len,
            client_identifier=client_id_placeholder,
        )

    except Exception as exc:
        logger.warning("Failed to parse DNS packet safely: %s", exc)
        return None


def parse_dict_event(data: Dict[str, Any]) -> Optional[ParsedDNSEvent]:
    """
    Parses an offline dictionary record (e.g. from sample JSON or CSV file) into ParsedDNSEvent.

    Args:
        data: Key-value dictionary containing event metadata.

    Returns:
        Optional[ParsedDNSEvent]: Validated event or None if unparseable.
    """
    try:
        raw_domain = str(data.get("queried_domain") or data.get("domain") or "").strip()
        if not raw_domain:
            return None

        normalized = normalize_domain(raw_domain).normalized_domain

        source_ip = str(data.get("client_ip") or data.get("source_ip") or "127.0.0.1")
        dest_ip = str(data.get("destination_ip") or data.get("resolver_ip") or "8.8.8.8")
        qtype = str(data.get("query_type") or "A").upper()
        rcode = str(data.get("response_code") or "NOERROR").upper()

        resp_data = data.get("response_data") or []
        if isinstance(resp_data, str):
            resp_data = [item.strip() for item in resp_data.split(",") if item.strip()]

        ttl_val = data.get("ttl")
        ttl = int(ttl_val) if ttl_val is not None and str(ttl_val).isdigit() else None

        pkt_len = data.get("packet_length")
        packet_length = int(pkt_len) if pkt_len is not None and str(pkt_len).isdigit() else len(raw_domain) + 40

        timestamp = str(data.get("timestamp") or _current_iso_timestamp())
        is_response = bool(data.get("is_response", False))
        txid = int(data.get("transaction_id", 1234)) if data.get("transaction_id") else None

        client_id = str(data.get("client_identifier") or f"host_{source_ip.replace('.', '_')}")

        return ParsedDNSEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=int(data.get("source_port", 50000)),
            destination_port=int(data.get("destination_port", 53)),
            protocol=str(data.get("protocol", "UDP")).upper(),
            transaction_id=txid,
            is_response=is_response,
            queried_domain=normalized,
            raw_domain=raw_domain,
            query_type=qtype,
            response_code=rcode,
            response_data=resp_data,
            ttl=ttl,
            packet_length=packet_length,
            client_identifier=client_id,
        )

    except Exception as exc:
        logger.warning("Error parsing dictionary event: %s", exc)
        return None
