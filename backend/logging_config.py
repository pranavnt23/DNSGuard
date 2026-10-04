"""
Centralized structured logging configuration for DNSGuard.
Provides consistent formatting across console and rotating file output.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    log_level: Optional[str] = None,
    log_file_path: Optional[str] = None,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    """
    Configures and initializes the root logger for DNSGuard.
    
    Args:
        log_level: Optional logging level string (DEBUG, INFO, WARNING, ERROR).
        log_file_path: Optional destination for rotating log file.
        max_bytes: Max file size before rotation (default: 5MB).
        backup_count: Number of rotated log archives to retain.
        
    Returns:
        The configured root logger instance.
    """
    level_str = (log_level or "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers if already initialized
    if root_logger.handlers:
        root_logger.handlers.clear()

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    # Console Handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Rotating File Handler
    target_file = log_file_path or "./data/dnsguard.log"
    try:
        Path(target_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=target_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except Exception as exc:
        root_logger.warning("Could not initialize file log handler at %s: %s", target_file, exc)

    # Silence overly verbose external libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.WARNING)

    root_logger.info("DNSGuard logging initialized at level %s", level_str)
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Convenience helper to obtain a named logger under DNSGuard namespace.
    """
    return logging.getLogger(f"dnsguard.{name}")
