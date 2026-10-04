"""
End-to-End DNS Processing Pipeline for DNSGuard.

Coordinates the complete flow:
    Packet / Sample
          ↓
    Collector
          ↓
    Parser & Normalizer
          ↓
    Feature Extractor
          ↓
    SQLite Persistence (DNSRepository)
          ↓
    Ready for Threat Detection (Prompt 3)
"""

import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.logging_config import get_logger
from database.models import DNSEvent, DetectionStatus, ExtractedFeatures
from database.repository import DNSRepository
from dns_engine.collector import DNSCollector
from dns_engine.domain_context import DomainContextProvider, get_domain_context_provider
from dns_engine.features import extract_features, ClientActivityTracker, get_activity_tracker
from dns_engine.parser import ParsedDNSEvent, parse_scapy_packet, parse_dict_event

logger = get_logger("pipeline")


class PipelineSummary(BaseModel):
    """Execution telemetry returned after a batch ingestion or capture run."""
    source_type: str = Field(description="pcap, json, csv, or live")
    total_read: int = 0
    processed: int = 0
    stored: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    event_ids: List[int] = Field(default_factory=list)


class DNSPipeline:
    """
    Unified ingestion pipeline decoupling raw packet parsing, normalization,
    feature extraction, and database persistence.
    """

    def __init__(
        self,
        repository: Optional[DNSRepository] = None,
        context_provider: Optional[DomainContextProvider] = None,
        tracker: Optional[ClientActivityTracker] = None,
    ):
        self.repo = repository or DNSRepository()
        self.context_provider = context_provider or get_domain_context_provider()
        self.tracker = tracker or get_activity_tracker()

    def process_parsed_event(
        self,
        parsed: ParsedDNSEvent,
        store: bool = True,
    ) -> Tuple[DNSEvent, ExtractedFeatures, Dict[str, Any]]:
        """
        Extracts features from a normalized ParsedDNSEvent, optionally persists it to SQLite,
        and returns the consolidated data objects.

        Args:
            parsed: Parsed and normalized DNS event.
            store: If True, writes the event to the SQLite database.

        Returns:
            Tuple[DNSEvent, ExtractedFeatures, Dict[str, Any]]:
                - DNSEvent: The database model instance (with populated id if stored).
                - ExtractedFeatures: Canonical feature vector for rule/ML detectors.
                - Dict[str, Any]: Full lexical, structural, and behavioral metrics dictionary.
        """
        # 1. Feature extraction
        features_model, extended_details = extract_features(
            domain=parsed.queried_domain,
            query_type=parsed.query_type,
            response_code=parsed.response_code,
            response_data=parsed.response_data,
            ttl=parsed.ttl,
            packet_length=parsed.packet_length,
            client_id=parsed.source_ip,
            tracker=self.tracker,
        )

        # 2. Domain Context Lookup (Age, Creation Date)
        domain_ctx = self.context_provider.get_context(parsed.queried_domain)
        extended_details["domain_age_days"] = domain_ctx.domain_age_days
        extended_details["is_recently_registered"] = domain_ctx.is_recently_registered
        extended_details["registrar"] = domain_ctx.registrar

        # 3. Create canonical DNSEvent model
        dns_event = DNSEvent(
            timestamp=parsed.timestamp,
            client_identifier=parsed.client_identifier,
            raw_client_ip=parsed.source_ip,
            queried_domain=parsed.queried_domain,
            query_type=parsed.query_type,
            response_code=parsed.response_code,
            response_data=parsed.response_data,
            ttl=parsed.ttl,
            packet_length=parsed.packet_length,
            protocol=parsed.protocol,
            source_port=parsed.source_port,
            destination_port=parsed.destination_port,
            extracted_features=extended_details,
            detection_status=DetectionStatus.PENDING,
        )

        # 4. Persistence to SQLite
        if store:
            event_id = self.repo.insert_dns_event(dns_event)
            dns_event.id = event_id
            logger.debug("Stored DNS event #%d for domain '%s'", event_id, dns_event.queried_domain)

        return dns_event, features_model, extended_details

    def process_scapy_packet(
        self,
        pkt: Any,
        store: bool = True,
    ) -> Optional[Tuple[DNSEvent, ExtractedFeatures, Dict[str, Any]]]:
        """
        Parses a Scapy packet and pushes it through feature extraction and storage.
        """
        parsed = parse_scapy_packet(pkt)
        if not parsed:
            return None
        return self.process_parsed_event(parsed, store=store)

    def process_dict_event(
        self,
        data: Dict[str, Any],
        store: bool = True,
    ) -> Optional[Tuple[DNSEvent, ExtractedFeatures, Dict[str, Any]]]:
        """
        Parses an offline dictionary event and pushes it through feature extraction and storage.
        """
        parsed = parse_dict_event(data)
        if not parsed:
            return None
        return self.process_parsed_event(parsed, store=store)

    # ==========================================================================
    # Ingestion Workflows
    # ==========================================================================

    def ingest_pcap(self, pcap_path: str, max_packets: Optional[int] = None) -> PipelineSummary:
        """
        Ingests DNS events from an offline PCAP file.
        """
        start = time.time()
        packets = DNSCollector.read_pcap(pcap_path, max_packets=max_packets)
        summary = PipelineSummary(source_type="pcap", total_read=len(packets))

        for pkt in packets:
            try:
                res = self.process_scapy_packet(pkt, store=True)
                if res:
                    event, _, _ = res
                    summary.processed += 1
                    summary.stored += 1
                    if event.id:
                        summary.event_ids.append(event.id)
                else:
                    summary.errors += 1
            except Exception as exc:
                logger.warning("Error processing PCAP packet: %s", exc)
                summary.errors += 1

        summary.duration_seconds = round(time.time() - start, 2)
        logger.info(
            "PCAP ingestion complete: %d/%d stored in %.2fs",
            summary.stored,
            summary.total_read,
            summary.duration_seconds,
        )
        return summary

    def ingest_sample_file(self, file_path: str) -> PipelineSummary:
        """
        Ingests events from a JSON or CSV sample file.
        """
        start = time.time()
        ext = file_path.lower().split(".")[-1]

        if ext == "json":
            records = DNSCollector.read_sample_json(file_path)
            source_type = "json"
        elif ext == "csv":
            records = DNSCollector.read_sample_csv(file_path)
            source_type = "csv"
        elif ext in ("pcap", "pcapng"):
            return self.ingest_pcap(file_path)
        else:
            raise ValueError(f"Unsupported sample file extension: .{ext}")

        summary = PipelineSummary(source_type=source_type, total_read=len(records))

        for rec in records:
            try:
                res = self.process_dict_event(rec, store=True)
                if res:
                    event, _, _ = res
                    summary.processed += 1
                    summary.stored += 1
                    if event.id:
                        summary.event_ids.append(event.id)
                else:
                    summary.errors += 1
            except Exception as exc:
                logger.warning("Error processing sample record: %s", exc)
                summary.errors += 1

        summary.duration_seconds = round(time.time() - start, 2)
        logger.info(
            "%s ingestion complete: %d/%d stored in %.2fs",
            source_type.upper(),
            summary.stored,
            summary.total_read,
            summary.duration_seconds,
        )
        return summary

    def run_live_capture(
        self,
        interface: Optional[str] = None,
        packet_count: int = 15,
        timeout: int = 5,
    ) -> PipelineSummary:
        """
        Attempts a live DNS packet capture, parsing and storing each captured frame.
        """
        start = time.time()
        collector = DNSCollector(interface=interface)
        summary = PipelineSummary(source_type="live")

        def _packet_callback(pkt: Any) -> None:
            res = self.process_scapy_packet(pkt, store=True)
            if res:
                event, _, _ = res
                summary.processed += 1
                summary.stored += 1
                if event.id:
                    summary.event_ids.append(event.id)
            else:
                summary.errors += 1

        capture_res, packets = collector.capture_live(
            packet_count=packet_count,
            timeout=timeout,
            packet_callback=_packet_callback,
            store=False,
        )

        summary.total_read = capture_res.packet_count
        summary.duration_seconds = round(time.time() - start, 2)
        return summary
