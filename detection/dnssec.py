"""
DNSSEC Validation & Status Interface for DNSGuard.

Provides a clean detection interface for DNSSEC validation:
- Distinguishes VALID, INVALID, and UNKNOWN.
- Never treats UNKNOWN as INVALID.
- Safely inspects DNS Header AD (Authenticated Data) and CD (Checking Disabled) flags.
- Does not fabricate validation results when DNSSEC signatures are absent.
"""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, ConfigDict


class DNSSECStatus(str, Enum):
    """Tri-state DNSSEC validation outcome."""
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class DNSSECValidationResult(BaseModel):
    """Outcome of DNSSEC security analysis."""
    status: DNSSECStatus = Field(default=DNSSECStatus.UNKNOWN)
    authenticated_data: bool = Field(default=False, description="DNS Header AD bit set by validating resolver")
    checking_disabled: bool = Field(default=False, description="DNS Header CD bit")
    reason: str = Field(default="No DNSSEC validation data available; status marked as unknown")

    model_config = ConfigDict(from_attributes=True)


def evaluate_dnssec(
    event_data: Optional[Dict[str, Any]] = None,
    raw_packet: Optional[Any] = None,
) -> DNSSECValidationResult:
    """
    Evaluates DNSSEC flags and security status for a DNS event.

    Args:
        event_data: Dictionary of event metadata or extracted features.
        raw_packet: Optional raw Scapy DNS packet.

    Returns:
        DNSSECValidationResult: Categorized as valid, invalid, or unknown.
    """
    # 1. Check raw Scapy packet if available
    if raw_packet is not None and hasattr(raw_packet, "haslayer"):
        try:
            from scapy.layers.dns import DNS
            if raw_packet.haslayer(DNS):
                dns_layer = raw_packet[DNS]
                ad_bit = bool(getattr(dns_layer, "ad", 0))
                cd_bit = bool(getattr(dns_layer, "cd", 0))

                if ad_bit:
                    return DNSSECValidationResult(
                        status=DNSSECStatus.VALID,
                        authenticated_data=True,
                        checking_disabled=cd_bit,
                        reason="DNSSEC Authenticated Data (AD) bit asserted by recursive resolver",
                    )
        except Exception:
            pass

    # 2. Check event dictionary if available
    if event_data:
        dnssec_field = event_data.get("dnssec_status")
        if dnssec_field:
            status_str = str(dnssec_field).lower()
            if status_str in ("valid", "secure"):
                return DNSSECValidationResult(
                    status=DNSSECStatus.VALID,
                    authenticated_data=True,
                    reason="Explicit DNSSEC validation recorded as secure",
                )
            elif status_str in ("invalid", "bogus", "failed"):
                return DNSSECValidationResult(
                    status=DNSSECStatus.INVALID,
                    authenticated_data=False,
                    reason="DNSSEC signature verification failed (BOGUS response)",
                )

    # 3. Default fallback: UNKNOWN (never assume invalid)
    return DNSSECValidationResult(
        status=DNSSECStatus.UNKNOWN,
        authenticated_data=False,
        checking_disabled=False,
        reason="DNSSEC validation information unavailable in query/response; marked as unknown",
    )
