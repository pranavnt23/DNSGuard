"""
DNSGuard DNS Engine Module.
Owned by: Member 1 (Threat Detection)

This module handles:
- Live DNS packet capture (Scapy / raw sockets) and offline PCAP ingestion
- DNS packet dissection and parsing (dnspython / Scapy)
- Lexical, structural, and behavioral feature extraction from DNS queries/responses
"""

__version__ = "0.1.0"
