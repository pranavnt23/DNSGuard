"""
Domain name normalization and validation module for DNSGuard.

Conforms to RFC 1035 / RFC 1123 standards while preserving forensic integrity:
- Case normalization (lowercased)
- Trailing dot stripping
- Whitespace stripping
- RFC structural constraints validation (max 253 chars, max 63 chars per label)
- Preserves raw input domain for audit and forensic examination
"""

import re
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict

# RFC 1035 / RFC 1123 label regex: alphanumeric, can contain internal hyphens
RFC_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Multi-part TLDs commonly used across global registries
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "ne.jp", "ac.jp",
    "com.br", "net.br", "gov.br",
    "co.za", "org.za",
}


class NormalizedDomain(BaseModel):
    """
    Structured domain representation containing both raw and parsed components.
    """
    raw_domain: str = Field(description="Unaltered raw domain as captured from the network")
    normalized_domain: str = Field(description="Standardized lowercase domain without trailing dots")
    labels: List[str] = Field(default_factory=list, description="Ordered list of dot-separated labels")
    tld: str = Field(default="", description="Top-Level Domain (e.g. 'com', 'co.uk')")
    sld: str = Field(default="", description="Second-Level Domain / Registrable root (e.g. 'example')")
    subdomains: List[str] = Field(default_factory=list, description="Subdomain labels above the SLD")
    subdomain_depth: int = Field(default=0, description="Count of subdomain levels")
    is_valid: bool = Field(default=True, description="Whether the domain satisfies structural DNS conventions")
    error_message: Optional[str] = Field(default=None, description="Diagnostic reason if marked invalid")

    model_config = ConfigDict(from_attributes=True)


def normalize_domain(raw_domain: Optional[str]) -> NormalizedDomain:
    """
    Parses, validates, and normalizes a domain string.

    Args:
        raw_domain: The raw domain string (may have trailing dot, mixed case, or whitespace).

    Returns:
        NormalizedDomain: Strongly-typed model containing normalized string, labels, TLD, SLD,
                          and structural validity flags.
    """
    original = "" if raw_domain is None else str(raw_domain)
    stripped = original.strip()

    # Handle completely empty domain
    if not stripped:
        return NormalizedDomain(
            raw_domain=original,
            normalized_domain="",
            labels=[],
            tld="",
            sld="",
            subdomains=[],
            subdomain_depth=0,
            is_valid=False,
            error_message="Domain name is empty",
        )

    # Normalize case and remove trailing dot (DNS root zone indicator)
    normalized = stripped.rstrip(".").lower()

    if not normalized:
        # Root zone query "."
        return NormalizedDomain(
            raw_domain=original,
            normalized_domain=".",
            labels=[],
            tld="",
            sld="",
            subdomains=[],
            subdomain_depth=0,
            is_valid=True,
            error_message=None,
        )

    # Check maximum total length (RFC 1035: max 253 characters)
    if len(normalized) > 253:
        return NormalizedDomain(
            raw_domain=original,
            normalized_domain=normalized,
            labels=normalized.split("."),
            tld="",
            sld="",
            subdomains=[],
            subdomain_depth=0,
            is_valid=False,
            error_message=f"Total domain length exceeds RFC 1035 limit of 253 characters ({len(normalized)})",
        )

    labels = normalized.split(".")

    # Check for consecutive dots or empty labels (e.g. "foo..bar.com")
    if any(len(label) == 0 for label in labels):
        return NormalizedDomain(
            raw_domain=original,
            normalized_domain=normalized,
            labels=[lbl for lbl in labels if lbl],
            tld="",
            sld="",
            subdomains=[],
            subdomain_depth=0,
            is_valid=False,
            error_message="Domain contains consecutive dots or empty labels",
        )

    # Check individual label lengths (RFC 1035: max 63 characters per label)
    for idx, label in enumerate(labels):
        if len(label) > 63:
            return NormalizedDomain(
                raw_domain=original,
                normalized_domain=normalized,
                labels=labels,
                tld="",
                sld="",
                subdomains=[],
                subdomain_depth=0,
                is_valid=False,
                error_message=f"Label '{label[:15]}...' at index {idx} exceeds 63 character limit ({len(label)} chars)",
            )

    # Extract TLD, SLD, and Subdomains
    tld = ""
    sld = ""
    subdomains: List[str] = []

    if len(labels) == 1:
        # Single label (e.g., "localhost" or intranet host)
        sld = labels[0]
        tld = ""
        subdomains = []
    elif len(labels) >= 2:
        # Check for multi-part TLD (e.g. "co.uk" or "co.in")
        potential_two_part_tld = f"{labels[-2]}.{labels[-1]}"
        if potential_two_part_tld in MULTI_PART_TLDS and len(labels) >= 3:
            tld = potential_two_part_tld
            sld = labels[-3]
            subdomains = labels[:-3]
        else:
            tld = labels[-1]
            sld = labels[-2]
            subdomains = labels[:-2]

    # RFC label character conformity check (informational; non-conformity doesn't erase forensic value)
    is_structurally_valid = True
    error_msg = None

    for label in labels:
        if not RFC_LABEL_REGEX.match(label):
            # Might contain underscores, international chars, or base64 chars (common in tunneling/mDNS)
            is_structurally_valid = False
            error_msg = f"Label '{label}' contains non-standard characters (e.g. underscores or symbols)"
            break

    return NormalizedDomain(
        raw_domain=original,
        normalized_domain=normalized,
        labels=labels,
        tld=tld,
        sld=sld,
        subdomains=subdomains,
        subdomain_depth=len(subdomains),
        is_valid=is_structurally_valid,
        error_message=error_msg,
    )


def clean_domain_string(domain: Optional[str]) -> str:
    """
    Convenience function returning just the normalized domain string.
    """
    if domain is None:
        return ""
    return domain.strip().rstrip(".").lower()
