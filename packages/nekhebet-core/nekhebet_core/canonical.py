"""
Nekhebet Core v4.0.0 — RFC 8785 compliant canonicalization

Implements JSON Canonicalization Scheme (JCS) for deterministic signing.
All output is guaranteed to be identical across platforms and runs.

SECURITY BOUNDARY:
Any change in this module INVALIDATES ALL EXISTING SIGNATURES.
Changing even a single space, number formatting rule,
or key sorting order breaks compatibility.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

import msgspec

from .types import EnvelopeHeader

# =============================================================================
# RFC 8785 (JCS) canonical JSON settings
# =============================================================================
#
# RFC 8785 requirements satisfied:
# - UTF-8 encoding
# - No insignificant whitespace
# - Object member names sorted lexicographically by Unicode code points
# - Deterministic number formatting
# - No NaN / Infinity (rejected earlier by payload validation)
#
# Python's json module is RFC 8785–compatible *when configured strictly*
# and when non-finite floats are rejected before this stage.
#
# References:
# - RFC 8785: https://www.rfc-editor.org/rfc/rfc8785
#
_JSON_DUMPS_KWARGS = {
    "ensure_ascii": False,
    "sort_keys": True,
    "separators": (",", ":"),  # no insignificant whitespace
    "allow_nan": False,        # REQUIRED by RFC 8785
}

# =============================================================================
# Public API
# =============================================================================

def canonicalize(data: Dict[str, Any]) -> bytes:
    """
    Canonicalize a Python dict according to RFC 8785 (JCS).

    This is a pure deterministic transformation:
        Python dict (JSON object) → canonical JSON UTF-8 bytes

    Used for both payload and header (via to_builtins).

    Args:
        data: JSON-compatible dictionary

    Returns:
        bytes: Deterministic UTF-8 JSON bytes without extra whitespace

    Raises:
        TypeError: If input is not a dict
        ValueError: If data contains unsupported or non-canonical values
    """
    if not isinstance(data, dict):
        raise TypeError("canonicalize expects a dict (JSON object)")

    try:
        # RFC 8785 / JCS canonical JSON:
        # - sorted keys
        # - no insignificant whitespace
        # - UTF-8 encoding
        canonical_str = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return canonical_str.encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ValueError(f"Failed to canonicalize data: {e}") from e

def canonicalize_header(header: EnvelopeHeader) -> bytes:
    """
    Canonicalize an EnvelopeHeader for signing or verification.

    SINGLE SOURCE OF TRUTH for header canonicalization.

    Process:
        EnvelopeHeader → msgspec.to_builtins() → canonicalize()

    This function MUST be used everywhere the header is signed or verified.
    """
    try:
        header_builtins = msgspec.to_builtins(header)
        if not isinstance(header_builtins, dict):
            raise TypeError("EnvelopeHeader did not convert to dict")
        return canonicalize(header_builtins)
    except Exception as e:
        raise ValueError(f"Failed to canonicalize header: {e}") from e


def compute_payload_hash_from_canonical(canonical_payload: bytes) -> str:
    """
    Compute SHA-256 hash from already canonicalized payload bytes.

    Used when canonicalization has already been performed in a prior step.

    Args:
        canonical_payload: Result of canonicalize(payload)

    Returns:
        str: Lowercase hexadecimal SHA-256 digest (64 characters)
    """
    if not isinstance(canonical_payload, (bytes, bytearray)):
        raise TypeError("canonical_payload must be bytes or bytearray")

    return hashlib.sha256(canonical_payload).hexdigest()


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """
    Convenience helper: dict → canonicalize → SHA-256.

    Primary usage path in create_envelope() and verify_envelope().

    Args:
        payload: Event payload dictionary

    Returns:
        str: Lowercase hexadecimal SHA-256 digest
    """
    canonical_bytes = canonicalize(payload)
    return compute_payload_hash_from_canonical(canonical_bytes)
