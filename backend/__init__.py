"""
DNSGuard Backend Module.
Configuration, structured logging, schemas, and FastAPI service entry point.
"""

from backend.config import get_settings, Settings
from backend.logging_config import setup_logging

__all__ = ["get_settings", "Settings", "setup_logging"]
