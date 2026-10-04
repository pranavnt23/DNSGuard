"""
Unit tests for DNS packet and dictionary parsing in DNSGuard.
"""

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from dns_engine.parser import parse_scapy_packet, parse_dict_event


def test_parse_scapy_dns_query():
    """Verify parsing of standard DNS query packet."""
    pkt = (
        IP(src="192.168.1.50", dst="8.8.8.8")
        / UDP(sport=51234, dport=53)
        / DNS(id=4321, qr=0, qd=DNSQR(qname="test-query.org.", qtype="A"))
    )

    event = parse_scapy_packet(pkt)
    assert event is not None
    assert event.source_ip == "192.168.1.50"
    assert event.destination_ip == "8.8.8.8"
    assert event.queried_domain == "test-query.org"
    assert event.query_type == "A"
    assert event.is_response is False
    assert event.transaction_id == 4321


def test_parse_scapy_dns_response_with_answers():
    """Verify parsing of DNS response packet with answer IPs and TTL."""
    pkt = (
        IP(src="8.8.8.8", dst="192.168.1.50")
        / UDP(sport=53, dport=51234)
        / DNS(
            id=4321,
            qr=1,
            rcode=0,
            qd=DNSQR(qname="test-query.org.", qtype="A"),
            an=DNSRR(rrname="test-query.org.", type="A", rdata="93.184.216.34", ttl=300),
        )
    )

    event = parse_scapy_packet(pkt)
    assert event is not None
    assert event.is_response is True
    assert event.response_code == "NOERROR"
    assert "93.184.216.34" in event.response_data
    assert event.ttl == 300


def test_parse_dict_event():
    """Verify parsing from dictionary record (offline sample format)."""
    raw_dict = {
        "client_ip": "10.0.0.15",
        "domain": "api.service.internal.",
        "query_type": "AAAA",
        "response_code": "NOERROR",
        "response_data": ["2001:db8::1"],
        "ttl": 120,
    }

    event = parse_dict_event(raw_dict)
    assert event is not None
    assert event.source_ip == "10.0.0.15"
    assert event.queried_domain == "api.service.internal"
    assert event.query_type == "AAAA"
    assert event.ttl == 120
    assert event.response_data == ["2001:db8::1"]


def test_malformed_packet_handling_no_crash():
    """Verify that non-DNS or malformed packets return None without raising uncaught exceptions."""
    # 1. Packet without DNS layer
    non_dns_pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=1234)
    assert parse_scapy_packet(non_dns_pkt) is None

    # 2. Non-packet object
    assert parse_scapy_packet("not a packet") is None
    assert parse_scapy_packet(None) is None

    # 3. DNS packet without Question Section
    empty_dns = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=53) / DNS(id=999, qd=None)
    parsed = parse_scapy_packet(empty_dns)
    # Handled gracefully, not raising exceptions
    assert parsed is not None
    assert parsed.queried_domain == "unknown"
