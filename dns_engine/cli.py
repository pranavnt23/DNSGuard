"""
Command-Line Demonstration & Execution Interface for DNSGuard DNS Engine.

Usage:
    # 1. Generate synthetic benchmark dataset (JSON, CSV, PCAP)
    python -m dns_engine.cli --generate-samples

    # 2. Ingest offline sample dataset into SQLite
    python -m dns_engine.cli --ingest-sample data/sample_dns_traffic.json

    # 3. Ingest offline PCAP capture file into SQLite
    python -m dns_engine.cli --ingest-pcap data/sample_dns_traffic.pcap

    # 4. Attempt a short live DNS packet capture (with graceful error handling)
    python -m dns_engine.cli --capture --timeout 5 --count 10

    # 5. Inspect and extract features for any domain
    python -m dns_engine.cli --inspect aW5mby1leGZpbHRyYXRpb24tcGF5bG9hZA.tunnel.evilcorp.net

    # 6. View database stored event statistics
    python -m dns_engine.cli --stats
"""

import argparse
import json
import sys
from typing import Optional

from backend.logging_config import setup_logging, get_logger
from database.connection import initialize_database
from database.repository import DNSRepository
from dns_engine.collector import DNSCollector
from dns_engine.features import extract_features
from dns_engine.pipeline import DNSPipeline
from dns_engine.sample_data import save_sample_dataset_files

logger = get_logger("cli")


def cmd_generate_samples(data_dir: str) -> None:
    print(f"\n[+] Generating synthetic DNS datasets in '{data_dir}'...")
    paths = save_sample_dataset_files(data_dir=data_dir)
    print("    [OK] JSON Sample: ", paths.get("json"))
    print("    [OK] CSV Sample:  ", paths.get("csv"))
    print("    [OK] PCAP Trace:  ", paths.get("pcap"))
    print("[+] Done. All synthetic sample formats are ready for demonstration.\n")


def cmd_ingest_sample(file_path: str) -> None:
    print(f"\n[+] Ingesting sample records from: {file_path}")
    pipeline = DNSPipeline()
    summary = pipeline.ingest_sample_file(file_path)
    print(f"    [OK] Source:      {summary.source_type.upper()}")
    print(f"    [OK] Total Read:  {summary.total_read}")
    print(f"    [OK] Processed:   {summary.processed}")
    print(f"    [OK] Stored:      {summary.stored} event(s) in SQLite database")
    print(f"    [OK] Duration:    {summary.duration_seconds}s")
    if summary.errors:
        print(f"    [!] Errors:       {summary.errors}")
    print("[+] Ingestion successful.\n")


def cmd_ingest_pcap(pcap_path: str, max_packets: Optional[int]) -> None:
    print(f"\n[+] Ingesting PCAP trace from: {pcap_path}")
    pipeline = DNSPipeline()
    summary = pipeline.ingest_pcap(pcap_path, max_packets=max_packets)
    print(f"    [OK] Total DNS:   {summary.total_read}")
    print(f"    [OK] Stored:      {summary.stored} event(s) in SQLite database")
    print(f"    [OK] Duration:    {summary.duration_seconds}s")
    print("[+] PCAP ingestion successful.\n")


def cmd_capture(timeout: int, count: int, interface: Optional[str]) -> None:
    print(f"\n[+] Checking live packet sniffing environment...")
    available, msg = DNSCollector.is_live_capture_available()
    print(f"    Status: {msg}")

    print(f"[+] Attempting live DNS capture (timeout={timeout}s, max_packets={count})...")
    pipeline = DNSPipeline()
    summary = pipeline.run_live_capture(interface=interface, packet_count=count, timeout=timeout)
    print(f"    [OK] Captured:    {summary.total_read} packet(s)")
    print(f"    [OK] Stored:      {summary.stored} event(s) in SQLite database")
    print(f"    [OK] Duration:    {summary.duration_seconds}s")
    if summary.total_read == 0:
        print("    [*] Tip: Generate DNS traffic locally (e.g. 'nslookup google.com') during capture,")
        print("        or run with offline PCAP/sample demonstration mode.")
    print("[+] Capture session ended.\n")


def cmd_inspect(domain: str) -> None:
    print(f"\n[+] Extracting lexical, structural, and statistical features for:")
    print(f"    Domain: '{domain}'\n")

    features_model, details = extract_features(domain=domain)

    print("--- Canonical ExtractedFeatures (Prompt 3 Input) ---")
    print(json.dumps(features_model.model_dump(), indent=2))

    print("\n--- Key Threat Indicator Signals ---")
    print(f"  * Shannon Entropy:         {details.get('shannon_entropy')} (Benchmark: >3.8 often signals DGA)")
    print(f"  * Max Label Entropy:       {details.get('max_label_entropy')}")
    print(f"  * Domain Length:           {details.get('domain_length')}")
    print(f"  * Longest Label Length:    {details.get('longest_label_length')} (Benchmark: >=40 signals Tunneling)")
    print(f"  * Has Suspicious Length:   {details.get('has_suspicious_long_label')}")
    print(f"  * Resembles Hex/Base32:    {details.get('has_hex_or_base32')}")
    print(f"  * Vowel Ratio:             {details.get('vowel_ratio')}")
    print(f"  * Max Consonant Run:       {details.get('max_consonant_sequence')}")
    print(f"  * Subdomain Depth:         {details.get('subdomain_depth')}")
    print(f"  * Structurally RFC-Valid:  {details.get('is_structurally_valid')}\n")


def cmd_stats() -> None:
    print("\n[+] Querying SQLite database status...")
    repo = DNSRepository()
    events = repo.list_dns_events(limit=500)
    print(f"    Total Events in Store: {len(events)}")

    if events:
        qtypes = {}
        for ev in events:
            qtypes[ev.query_type] = qtypes.get(ev.query_type, 0) + 1

        print("    Query Type Breakdown:")
        for qt, count in sorted(qtypes.items()):
            print(f"      - {qt:<6}: {count}")

        print("\n    Recent 5 Logged Events:")
        for ev in events[:5]:
            print(f"      [#{ev.id}] {ev.timestamp} | {ev.client_identifier} | {ev.query_type:<4} {ev.queried_domain} (TTL: {ev.ttl})")
    print("")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNSGuard DNS Engine CLI: Capture, parse, extract features, and ingest DNS events."
    )
    parser.add_argument("--generate-samples", action="store_true", help="Generate synthetic JSON, CSV, and PCAP datasets")
    parser.add_argument("--data-dir", default="./data", help="Directory for sample files (default: ./data)")
    parser.add_argument("--ingest-sample", type=str, nargs="?", const="data/sample_dns_traffic.json", help="Ingest a JSON/CSV sample file")
    parser.add_argument("--ingest-pcap", type=str, nargs="?", const="data/sample_dns_traffic.pcap", help="Ingest a PCAP capture file")
    parser.add_argument("--max-packets", type=int, default=None, help="Limit packets for PCAP ingestion")
    parser.add_argument("--capture", action="store_true", help="Attempt live DNS packet sniffing")
    parser.add_argument("--timeout", type=int, default=5, help="Capture timeout in seconds (default: 5)")
    parser.add_argument("--count", type=int, default=15, help="Max packets to capture (default: 15)")
    parser.add_argument("--interface", type=str, default=None, help="Network interface for live capture")
    parser.add_argument("--inspect", type=str, help="Extract and display feature vector for a domain")
    parser.add_argument("--stats", action="store_true", help="Display SQLite stored DNS events summary")

    args = parser.parse_args()

    # Ensure database is initialized
    setup_logging(log_level="INFO")
    initialize_database()

    if args.generate_samples:
        cmd_generate_samples(data_dir=args.data_dir)
    elif args.ingest_sample:
        cmd_ingest_sample(file_path=args.ingest_sample)
    elif args.ingest_pcap:
        cmd_ingest_pcap(pcap_path=args.ingest_pcap, max_packets=args.max_packets)
    elif args.capture:
        cmd_capture(timeout=args.timeout, count=args.count, interface=args.interface)
    elif args.inspect:
        cmd_inspect(domain=args.inspect)
    elif args.stats:
        cmd_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
