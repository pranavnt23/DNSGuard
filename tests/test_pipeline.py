"""
End-to-end integration tests for DNSPipeline with SQLite database storage.
"""

import pytest
from dns_engine.pipeline import DNSPipeline
from dns_engine.sample_data import save_sample_dataset_files
from database.repository import DNSRepository


def test_pipeline_process_and_store_single_event(temp_db: str):
    """Verify that a single parsed event flows through feature extraction and into SQLite."""
    repo = DNSRepository(db_path=temp_db)
    pipeline = DNSPipeline(repository=repo)

    raw_event = {
        "client_ip": "192.168.1.180",
        "domain": "google.com",
        "query_type": "A",
        "response_code": "NOERROR",
        "response_data": ["142.250.190.46"],
        "ttl": 300,
    }

    res = pipeline.process_dict_event(raw_event, store=True)
    assert res is not None
    dns_event, features_model, details = res

    # Check persistence
    assert dns_event.id is not None
    assert dns_event.id > 0

    # Retrieve from DB and verify
    stored = repo.get_dns_event(dns_event.id)
    assert stored is not None
    assert stored.queried_domain == "google.com"
    assert stored.extracted_features is not None
    assert "shannon_entropy" in stored.extracted_features
    assert stored.extracted_features["domain_age_days"] == 10500  # From mock provider


def test_pipeline_ingest_sample_json(temp_db: str, tmp_path):
    """Verify batch ingestion from sample JSON file."""
    repo = DNSRepository(db_path=temp_db)
    pipeline = DNSPipeline(repository=repo)

    # Generate sample files in tmp_path
    paths = save_sample_dataset_files(data_dir=str(tmp_path))
    json_path = paths["json"]

    summary = pipeline.ingest_sample_file(json_path)
    assert summary.source_type == "json"
    assert summary.total_read > 0
    assert summary.stored == summary.total_read
    assert summary.errors == 0

    # Check repository count
    events = repo.list_dns_events(limit=100)
    assert len(events) == summary.stored


def test_pipeline_ingest_sample_csv(temp_db: str, tmp_path):
    """Verify batch ingestion from sample CSV file."""
    repo = DNSRepository(db_path=temp_db)
    pipeline = DNSPipeline(repository=repo)

    paths = save_sample_dataset_files(data_dir=str(tmp_path))
    csv_path = paths["csv"]

    summary = pipeline.ingest_sample_file(csv_path)
    assert summary.source_type == "csv"
    assert summary.total_read > 0
    assert summary.stored == summary.total_read


def test_pipeline_ingest_pcap(temp_db: str, tmp_path):
    """Verify batch ingestion from binary PCAP capture trace."""
    repo = DNSRepository(db_path=temp_db)
    pipeline = DNSPipeline(repository=repo)

    paths = save_sample_dataset_files(data_dir=str(tmp_path))
    pcap_path = paths["pcap"]

    summary = pipeline.ingest_pcap(pcap_path)
    assert summary.source_type == "pcap"
    assert summary.total_read > 0
    assert summary.stored == summary.total_read
    assert summary.errors == 0
