"""
DNS Packet Collector module for DNSGuard.

Provides both live network sniffing (via Scapy) and robust offline ingestion
from PCAP files, CSV, and JSON data sources.
Defensively catches missing permissions or interface errors without crashing.
"""

import csv
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.config import get_settings
from backend.logging_config import get_logger

logger = get_logger("collector")

DEFAULT_BPF_FILTER = "udp port 53 or tcp port 53"


class CaptureResult(BaseModel):
    """Execution report returned after a live packet sniffing session."""
    success: bool
    packet_count: int = 0
    duration_seconds: float = 0.0
    interface: str = "default"
    filter: str = DEFAULT_BPF_FILTER
    error_message: Optional[str] = None


class DNSCollector:
    """
    Modular DNS traffic collector supporting live packet capture and offline file ingestion.
    """

    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None):
        settings = get_settings()
        self.interface = interface or settings.dns_interface
        self.bpf_filter = bpf_filter or DEFAULT_BPF_FILTER

    @staticmethod
    def is_live_capture_available() -> Tuple[bool, str]:
        """
        Probes the host operating system to determine if raw packet sniffing is permitted.
        Returns:
            Tuple[bool, str]: (is_available, human_readable_status)
        """
        try:
            import scapy.config
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            if not interfaces:
                return False, "No network interfaces detected by Scapy."
            return True, f"Live capture ready on {len(interfaces)} interface(s)."
        except Exception as exc:
            return False, f"Live capture unavailable: {exc}"

    def capture_live(
        self,
        packet_count: int = 20,
        timeout: int = 5,
        packet_callback: Optional[Callable[[Any], None]] = None,
        store: bool = True,
    ) -> Tuple[CaptureResult, List[Any]]:
        """
        Initiates a controlled live DNS packet sniffing session.

        Args:
            packet_count: Maximum packets to capture before stopping (0 for unlimited).
            timeout: Maximum capture duration in seconds.
            packet_callback: Optional function invoked per packet.
            store: Whether to return captured packets in memory.

        Returns:
            Tuple[CaptureResult, List[Any]]: Summary report and captured Scapy packets.
        """
        from scapy.all import sniff
        captured_packets: List[Any] = []
        start_time = time.time()

        # On Windows, 'any' interface is invalid; select None for Scapy default
        target_iface = None if (not self.interface or self.interface.lower() in ("any", "all")) else self.interface

        logger.info(
            "Starting live DNS capture (interface=%s, filter='%s', timeout=%ds, max_packets=%d)",
            target_iface or "auto",
            self.bpf_filter,
            timeout,
            packet_count,
        )

        def _internal_callback(pkt: Any) -> None:
            if store:
                captured_packets.append(pkt)
            if packet_callback:
                try:
                    packet_callback(pkt)
                except Exception as cb_err:
                    logger.debug("Error in packet callback: %s", cb_err)

        try:
            sniff_kwargs: Dict[str, Any] = {
                "filter": self.bpf_filter,
                "prn": _internal_callback,
                "timeout": timeout,
                "store": False,  # Managed in internal callback to control memory
            }
            if target_iface:
                sniff_kwargs["iface"] = target_iface
            if packet_count > 0:
                sniff_kwargs["count"] = packet_count

            sniff(**sniff_kwargs)

            elapsed = round(time.time() - start_time, 2)
            logger.info("Live capture complete: %d packet(s) captured in %.2fs", len(captured_packets), elapsed)

            return (
                CaptureResult(
                    success=True,
                    packet_count=len(captured_packets),
                    duration_seconds=elapsed,
                    interface=str(target_iface or "default"),
                    filter=self.bpf_filter,
                ),
                captured_packets,
            )

        except (PermissionError, OSError) as perm_err:
            elapsed = round(time.time() - start_time, 2)
            err_msg = (
                f"Insufficient privileges or missing Npcap/WinPcap driver for live capture: {perm_err}. "
                "Use offline PCAP/sample demonstration mode."
            )
            logger.warning(err_msg)
            return (
                CaptureResult(
                    success=False,
                    packet_count=len(captured_packets),
                    duration_seconds=elapsed,
                    interface=str(target_iface or "default"),
                    filter=self.bpf_filter,
                    error_message=err_msg,
                ),
                captured_packets,
            )
        except Exception as exc:
            elapsed = round(time.time() - start_time, 2)
            err_msg = f"Unexpected live capture failure: {exc}"
            logger.error(err_msg)
            return (
                CaptureResult(
                    success=False,
                    packet_count=len(captured_packets),
                    duration_seconds=elapsed,
                    interface=str(target_iface or "default"),
                    filter=self.bpf_filter,
                    error_message=err_msg,
                ),
                captured_packets,
            )

    @staticmethod
    def read_pcap(file_path: str, max_packets: Optional[int] = None) -> List[Any]:
        """
        Reads and extracts DNS packets from an offline PCAP/PCAPNG file using Scapy.

        Args:
            file_path: Absolute or relative path to .pcap or .pcapng file.
            max_packets: Optional limit on the number of packets to load.

        Returns:
            List[Any]: List of Scapy packet objects containing a DNS layer.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found at: {file_path}")

        from scapy.all import PcapReader
        from scapy.layers.dns import DNS

        dns_packets: List[Any] = []
        logger.info("Reading offline PCAP trace from: %s", path)

        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if pkt.haslayer(DNS):
                    dns_packets.append(pkt)
                    if max_packets and len(dns_packets) >= max_packets:
                        break

        logger.info("Successfully loaded %d DNS packet(s) from PCAP", len(dns_packets))
        return dns_packets

    @staticmethod
    def read_sample_json(file_path: str) -> List[Dict[str, Any]]:
        """
        Loads pre-recorded or synthetic DNS records from a JSON file.

        Args:
            file_path: Path to .json file.

        Returns:
            List[Dict[str, Any]]: List of dictionary event objects.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"JSON sample file not found at: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "events" in data:
            return data["events"]
        return [data]

    @staticmethod
    def read_sample_csv(file_path: str) -> List[Dict[str, Any]]:
        """
        Loads DNS records from a CSV file.

        Args:
            file_path: Path to .csv file.

        Returns:
            List[Dict[str, Any]]: List of record dictionaries.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"CSV sample file not found at: {file_path}")

        records: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(dict(row))
        return records
