"""
Domain Context & Registration Age interface module for DNSGuard.

Provides a modular abstraction for domain age, creation date, and registrar data.
Conforms to project constraints:
- Live WHOIS/network calls are strictly optional and never mandatory.
- The pipeline never crashes when domain age is unavailable.
- Unresolved domains cleanly yield domain_age_days = None.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional
from pydantic import BaseModel, Field, ConfigDict


class DomainContext(BaseModel):
    """
    Contextual information regarding a domain's registration lifecycle.
    """
    domain: str
    domain_age_days: Optional[int] = Field(default=None, description="Age in days since initial registration")
    creation_date: Optional[str] = Field(default=None, description="ISO registration date if known")
    registrar: Optional[str] = Field(default=None, description="Registrar name if known")
    is_recently_registered: Optional[bool] = Field(
        default=None,
        description="True if registered within the last 30 days (common DGA/phishing indicator)"
    )
    lookup_source: str = Field(default="none", description="Source of data: 'cache', 'synthetic', or 'none'")

    model_config = ConfigDict(from_attributes=True)


class DomainContextProvider(ABC):
    """Abstract interface for domain registration metadata lookup."""

    @abstractmethod
    def get_context(self, domain: str) -> DomainContext:
        """
        Retrieves registration context for the given domain.
        Must never raise exceptions; must return fallback DomainContext with None fields if unavailable.
        """
        pass


class MockDomainContextProvider(DomainContextProvider):
    """
    Offline mock and cache provider for reproducible tests and classroom demonstrations.
    Does not make any live network requests.
    """

    def __init__(self, custom_records: Optional[Dict[str, Dict]] = None):
        # Pre-seeded database for standard benign and synthetic test domains
        self._database: Dict[str, Dict] = {
            "google.com": {
                "age_days": 10500,
                "creation_date": "1997-09-15",
                "registrar": "MarkMonitor, Inc.",
            },
            "github.com": {
                "age_days": 6200,
                "creation_date": "2007-10-09",
                "registrar": "MarkMonitor, Inc.",
            },
            "wikipedia.org": {
                "age_days": 8700,
                "creation_date": "2001-01-13",
                "registrar": "MarkMonitor, Inc.",
            },
            "cloudflare.com": {
                "age_days": 5600,
                "creation_date": "2009-02-17",
                "registrar": "Cloudflare, Inc.",
            },
            "microsoft.com": {
                "age_days": 13000,
                "creation_date": "1991-05-02",
                "registrar": "Corporation Service Company",
            },
            # Synthetic malicious/test domains with newly-registered profiles
            "malicious-c2.cc": {
                "age_days": 2,
                "creation_date": "2026-10-01",
                "registrar": "Anonymous Offshore Registrar",
            },
            "fresh-dga.xyz": {
                "age_days": 1,
                "creation_date": "2026-10-02",
                "registrar": "Cheap Domain Reg Ltd",
            },
            "tunnel.evilcorp.net": {
                "age_days": 5,
                "creation_date": "2026-09-28",
                "registrar": "FastFlux Registrar Inc",
            },
        }
        if custom_records:
            self._database.update(custom_records)

    def get_context(self, domain: str) -> DomainContext:
        clean_domain = domain.strip().rstrip(".").lower()

        # Try exact domain or parent SLD
        record = self._database.get(clean_domain)
        if not record:
            parts = clean_domain.split(".")
            if len(parts) >= 2:
                parent_domain = f"{parts[-2]}.{parts[-1]}"
                record = self._database.get(parent_domain)

        if record:
            age = record.get("age_days")
            return DomainContext(
                domain=clean_domain,
                domain_age_days=age,
                creation_date=record.get("creation_date"),
                registrar=record.get("registrar"),
                is_recently_registered=(age is not None and age <= 30),
                lookup_source="synthetic_cache",
            )

        # Graceful fallback: return None values without error
        return DomainContext(
            domain=clean_domain,
            domain_age_days=None,
            creation_date=None,
            registrar=None,
            is_recently_registered=None,
            lookup_source="none",
        )


_default_provider = MockDomainContextProvider()


def get_domain_context_provider() -> DomainContextProvider:
    """Returns the default domain context provider instance."""
    return _default_provider
