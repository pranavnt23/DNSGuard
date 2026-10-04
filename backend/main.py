"""
DNSGuard FastAPI Application Entry Point.
Provides foundational health, diagnostic, and audit verification endpoints.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.logging_config import setup_logging, get_logger
from backend.schemas import SystemHealthResponse, SystemStatusResponse, AuditVerificationResponse
from database.connection import initialize_database, check_db_health
from database.repository import DNSRepository
from database.models import AuditEventType

# Set up logging on module load
settings = get_settings()
setup_logging(log_level=settings.log_level, log_file_path=settings.log_file_path)
logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application startup and shutdown lifecycle manager.
    Initializes database schema and logs boot events.
    """
    logger.info("Initializing DNSGuard service...")
    settings.ensure_directories()
    initialize_database()

    repo = DNSRepository()
    repo.insert_audit_log(
        event_type=AuditEventType.SYSTEM_INIT,
        user_or_component="api_server",
        details=f"DNSGuard FastAPI backend started on {settings.api_host}:{settings.api_port} in {settings.app_env} mode",
    )
    logger.info("DNSGuard startup sequence complete.")
    yield
    logger.info("DNSGuard shutting down.")


app = FastAPI(
    title="DNSGuard API",
    description="Intelligent DNS Security Monitoring and Threat Detection Framework API",
    version="0.1.0",
    lifespan=lifespan,
)

# Enable CORS for Streamlit dashboard and local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Root"])
def root_info() -> dict:
    """Basic root welcome endpoint."""
    return {
        "framework": "DNSGuard",
        "description": "Intelligent DNS Security Monitoring & Threat Detection Framework",
        "version": "0.1.0",
        "docs_url": "/docs",
        "health_endpoint": "/api/v1/health",
        "status_endpoint": "/api/v1/status",
    }


@app.get("/api/v1/health", response_model=SystemHealthResponse, tags=["Health"])
@app.get("/health", response_model=SystemHealthResponse, tags=["Health"])
def health_check() -> SystemHealthResponse:
    """
    Performs quick health verification across database and runtime components.
    """
    db_health = check_db_health()
    overall_status = "healthy" if db_health.get("healthy") else "degraded"

    return SystemHealthResponse(
        status=overall_status,
        database=db_health,
        app_name=settings.app_name,
        app_env=settings.app_env,
        version="0.1.0",
    )


@app.get("/api/v1/status", response_model=SystemStatusResponse, tags=["Diagnostics"])
def diagnostic_status() -> SystemStatusResponse:
    """
    Returns full diagnostic status including table counts and audit chain health.
    """
    repo = DNSRepository()
    db_health = check_db_health()
    table_counts = db_health.get("tables", {})
    alert_counts = repo.get_alert_counts_by_severity()

    chain_valid, _ = repo.verify_audit_log_integrity()

    return SystemStatusResponse(
        app_name=settings.app_name,
        environment=settings.app_env,
        debug=settings.debug,
        database_status="connected" if db_health.get("healthy") else "error",
        event_count=table_counts.get("dns_events", 0),
        alert_count=table_counts.get("alerts", 0),
        critical_alerts=alert_counts.get("CRITICAL", 0),
        audit_chain_valid=chain_valid,
        detection_thresholds={
            "dga_entropy": settings.dga_entropy_threshold,
            "dga_ngram": settings.dga_ngram_threshold,
            "tunneling_payload_len": settings.tunneling_payload_len_threshold,
            "spoofing_ttl_variance": settings.spoofing_ttl_variance_threshold,
            "burst_rate": settings.burst_query_rate_threshold,
        },
        risk_weights={
            "rule": settings.risk_weight_rule,
            "ml": settings.risk_weight_ml,
            "anomaly": settings.risk_weight_anomaly,
        },
    )


@app.get("/api/v1/audit/verify", response_model=AuditVerificationResponse, tags=["Security"])
def verify_audit_chain() -> AuditVerificationResponse:
    """
    Cryptographically verifies the SHA-256 hash chaining of the audit log table.
    """
    repo = DNSRepository()
    is_valid, message = repo.verify_audit_log_integrity()
    logs = repo.list_audit_logs(limit=1000)
    return AuditVerificationResponse(
        is_valid=is_valid,
        message=message or "Audit chain integrity verified.",
        total_records=len(logs),
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=settings.api_host, port=settings.api_port, reload=settings.debug)
