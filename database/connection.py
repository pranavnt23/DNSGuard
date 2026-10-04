"""
SQLite connection manager and database initializer for DNSGuard.
Configures WAL mode, enforces foreign key constraints, and handles schema setup.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
import hashlib

from backend.config import get_settings
from backend.logging_config import get_logger

logger = get_logger("database")

SCHEMA_FILE_PATH = Path(__file__).resolve().parent / "schema.sql"


class DatabaseConnection:
    """Helper class managing raw SQLite connections with safe pragmas."""

    def __init__(self, db_path: Optional[str] = None, timeout: Optional[float] = None):
        settings = get_settings()
        self.db_path = db_path or settings.database_path
        self.timeout = timeout if timeout is not None else settings.database_timeout

    def connect(self) -> sqlite3.Connection:
        """Opens and configures a new SQLite connection."""
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row

        # Essential Pragmas for security, integrity, and performance
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")

        return conn


@contextmanager
def get_db_connection(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager yielding a thread-safe configured SQLite connection.
    Ensures commit on success, rollback on error, and proper closing on exit.
    """
    db = DatabaseConnection(db_path=db_path)
    conn = db.connect()
    try:
        yield conn
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("Transaction rolled back due to error: %s", exc)
        raise
    finally:
        conn.close()


def initialize_database(db_path: Optional[str] = None) -> None:
    """
    Applies the DDL schema to create tables, indexes, and genesis audit record.
    Safe to call multiple times (idempotent).
    """
    settings = get_settings()
    target_path = db_path or settings.database_path
    logger.info("Initializing database schema at: %s", target_path)

    if not SCHEMA_FILE_PATH.exists():
        raise FileNotFoundError(f"Schema definition file not found at {SCHEMA_FILE_PATH}")

    with open(SCHEMA_FILE_PATH, "r", encoding="utf-8") as schema_file:
        ddl_script = schema_file.read()

    with get_db_connection(target_path) as conn:
        conn.executescript(ddl_script)

        # Check if audit_logs has the genesis block
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM audit_logs;")
        count = cursor.fetchone()["count"]

        if count == 0:
            genesis_prev = settings.audit_log_genesis_hash
            event_type = "SYSTEM_INIT"
            user_comp = "dnsguard_system"
            details = "Genesis block: DNSGuard framework database initialized"
            timestamp = "2026-01-01T00:00:00+00:00"

            # Compute entry hash for genesis
            raw_hash_data = f"{timestamp}|{event_type}|{user_comp}|{details}|{genesis_prev}"
            entry_hash = hashlib.sha256(raw_hash_data.encode("utf-8")).hexdigest()

            cursor.execute(
                """
                INSERT INTO audit_logs (timestamp, event_type, user_or_component, details, previous_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (timestamp, event_type, user_comp, details, genesis_prev, entry_hash),
            )
            logger.info("Inserted genesis audit log entry with entry_hash: %s", entry_hash[:16])

    logger.info("Database initialized successfully.")


def check_db_health(db_path: Optional[str] = None) -> dict:
    """
    Verifies SQLite connectivity, table existence, and schema integrity.
    """
    required_tables = {"dns_events", "detection_results", "alerts", "audit_logs"}
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = {row["name"] for row in cursor.fetchall()}

            missing = required_tables - existing_tables
            if missing:
                return {
                    "status": "degraded",
                    "healthy": False,
                    "error": f"Missing tables: {', '.join(missing)}",
                    "existing_tables": list(existing_tables),
                }

            # Count rows across core tables
            counts = {}
            for tbl in required_tables:
                cursor.execute(f"SELECT COUNT(*) AS cnt FROM {tbl};")
                counts[tbl] = cursor.fetchone()["cnt"]

            return {
                "status": "healthy",
                "healthy": True,
                "tables": counts,
            }
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        return {
            "status": "unhealthy",
            "healthy": False,
            "error": str(exc),
        }
