"""
DNSGuard DNS Engine Module.
Owned by: Member 1 (Threat Detection)

This module handles:
- Live DNS packet capture (Scapy) and offline ingestion (PCAP, CSV, JSON)
- Robust packet parsing and domain normalization
- Deterministic extraction of lexical, structural, statistical, and behavioral features
- Pipeline integration bridging packet ingestion and SQLite persistence
"""

from dns_engine.entropy import (
    calculate_shannon_entropy,
    calculate_label_entropies,
    max_label_entropy,
)
from dns_engine.normalizer import (
    normalize_domain,
    clean_domain_string,
    NormalizedDomain,
)
from dns_engine.domain_context import (
    DomainContext,
    DomainContextProvider,
    MockDomainContextProvider,
    get_domain_context_provider,
)
from dns_engine.features import (
    extract_features,
    ClientActivityTracker,
    get_activity_tracker,
)
from dns_engine.parser import (
    ParsedDNSEvent,
    parse_scapy_packet,
    parse_dict_event,
)
from dns_engine.collector import (
    DNSCollector,
    CaptureResult,
)
from dns_engine.pipeline import (
    DNSPipeline,
    PipelineSummary,
)
from dns_engine.sample_data import (
    generate_sample_dataset,
    save_sample_dataset_files,
)

__version__ = "0.2.0"

__all__ = [
    "calculate_shannon_entropy",
    "calculate_label_entropies",
    "max_label_entropy",
    "normalize_domain",
    "clean_domain_string",
    "NormalizedDomain",
    "DomainContext",
    "DomainContextProvider",
    "MockDomainContextProvider",
    "get_domain_context_provider",
    "extract_features",
    "ClientActivityTracker",
    "get_activity_tracker",
    "ParsedDNSEvent",
    "parse_scapy_packet",
    "parse_dict_event",
    "DNSCollector",
    "CaptureResult",
    "DNSPipeline",
    "PipelineSummary",
    "generate_sample_dataset",
    "save_sample_dataset_files",
]
