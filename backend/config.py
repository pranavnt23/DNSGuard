"""
Configuration management system for DNSGuard.
Loads settings from environment variables and optional .env file with robust validation.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration settings for DNSGuard framework.
    Default values allow zero-config development while allowing environment overrides.
    """

    # --- Application Metadata ---
    app_name: str = Field(default="DNSGuard", description="Name of the application")
    app_env: str = Field(default="development", description="Environment: development, testing, production")
    debug: bool = Field(default=True, description="Debug mode flag")
    api_host: str = Field(default="127.0.0.1", description="FastAPI host binding")
    api_port: int = Field(default=8000, description="FastAPI port")
    dashboard_port: int = Field(default=8501, description="Streamlit dashboard port")

    # --- Database Settings ---
    database_path: str = Field(
        default="./data/dnsguard.db",
        description="Path to SQLite database file"
    )
    database_timeout: float = Field(
        default=15.0,
        description="SQLite connection timeout in seconds"
    )

    # --- Security & Cryptography (Member 2) ---
    hmac_secret_salt: str = Field(
        default="dnsguard_dev_hmac_secret_salt_32b_min!",
        description="Salt/Secret key for HMAC-SHA256 client IP pseudonymisation"
    )
    aes_encryption_key_hex: str = Field(
        default="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        description="32-byte hex key for AES-256-GCM encryption of sensitive payloads"
    )
    audit_log_genesis_hash: str = Field(
        default="0000000000000000000000000000000000000000000000000000000000000000",
        description="Genesis previous_hash for the tamper-evident audit log chain"
    )

    # --- DNS Engine Settings (Member 1) ---
    dns_interface: str = Field(default="any", description="Network interface for live capture")
    dns_port: int = Field(default=53, description="DNS service port")
    dns_capture_buffer_size: int = Field(default=1000, description="Max packets in memory ring buffer")
    pcap_storage_path: str = Field(default="./data/captures", description="Directory to store captured PCAPs")

    # --- Detection Thresholds (Member 1) ---
    dga_entropy_threshold: float = Field(default=3.8, description="Shannon entropy threshold for DGA detection")
    dga_ngram_threshold: float = Field(default=0.35, description="N-gram score threshold for DGA detection")
    tunneling_payload_len_threshold: int = Field(default=45, description="Label length threshold for DNS tunneling")
    spoofing_ttl_variance_threshold: int = Field(default=60, description="TTL jitter threshold for cache poisoning")
    burst_query_rate_threshold: int = Field(default=25, description="Queries per second threshold per client")

    # --- Risk Scoring & Alert Thresholds (Member 2) ---
    risk_weight_rule: float = Field(default=0.40, description="Weight of rule-based score in final risk calculation")
    risk_weight_ml: float = Field(default=0.40, description="Weight of ML score in final risk calculation")
    risk_weight_anomaly: float = Field(default=0.20, description="Weight of anomaly score in final risk calculation")
    alert_threshold_low: float = Field(default=30.0, description="Score cutoff for Low severity")
    alert_threshold_medium: float = Field(default=55.0, description="Score cutoff for Medium severity")
    alert_threshold_high: float = Field(default=75.0, description="Score cutoff for High severity")
    alert_threshold_critical: float = Field(default=90.0, description="Score cutoff for Critical severity")

    # --- Logging ---
    log_level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)")
    log_file_path: str = Field(default="./data/dnsguard.log", description="Path for persistent log file")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("aes_encryption_key_hex")
    @classmethod
    def validate_aes_key(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) != 64:
            raise ValueError(
                f"aes_encryption_key_hex must be exactly 64 hex characters (32 bytes for AES-256), got {len(clean)}"
            )
        try:
            bytes.fromhex(clean)
        except ValueError as err:
            raise ValueError("aes_encryption_key_hex contains invalid non-hex characters") from err
        return clean

    @property
    def aes_key_bytes(self) -> bytes:
        """Returns the decoded 32 bytes for AES-256."""
        return bytes.fromhex(self.aes_encryption_key_hex)

    def ensure_directories(self) -> None:
        """Ensures that runtime directories for database, pcaps, and logs exist."""
        db_dir = Path(self.database_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        pcap_dir = Path(self.pcap_storage_path)
        pcap_dir.mkdir(parents=True, exist_ok=True)

        log_dir = Path(self.log_file_path).parent
        log_dir.mkdir(parents=True, exist_ok=True)


@lru_cache()
def get_settings() -> Settings:
    """Cached singleton getter for application settings."""
    settings = Settings()
    settings.ensure_directories()
    return settings
