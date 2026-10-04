"""
Unit tests for DNSGuard configuration management and validation.
"""

import pytest
from pydantic import ValidationError
from backend.config import Settings, get_settings


def test_default_settings_load():
    """Verify that default settings load without error and have sensible defaults."""
    settings = get_settings()
    assert settings.app_name == "DNSGuard"
    assert settings.api_port == 8000
    assert settings.database_path is not None
    assert len(settings.aes_key_bytes) == 32
    assert settings.dga_entropy_threshold > 0.0


def test_valid_aes_key():
    """Verify that a valid 64-character hex key (32 bytes) is accepted."""
    valid_key = "a" * 64
    settings = Settings(aes_encryption_key_hex=valid_key)
    assert settings.aes_encryption_key_hex == valid_key
    assert len(settings.aes_key_bytes) == 32


def test_invalid_aes_key_length():
    """Verify that an AES key of improper length raises ValidationError."""
    with pytest.raises(ValidationError):
        Settings(aes_encryption_key_hex="12345678")


def test_invalid_aes_key_characters():
    """Verify that non-hex characters in AES key raise ValidationError."""
    with pytest.raises(ValidationError):
        Settings(aes_encryption_key_hex="z" * 64)


def test_risk_weights_configuration():
    """Verify that risk scoring weights are positive floats."""
    settings = get_settings()
    assert settings.risk_weight_rule >= 0.0
    assert settings.risk_weight_ml >= 0.0
    assert settings.risk_weight_anomaly >= 0.0
    assert (settings.risk_weight_rule + settings.risk_weight_ml + settings.risk_weight_anomaly) == pytest.approx(1.0)
