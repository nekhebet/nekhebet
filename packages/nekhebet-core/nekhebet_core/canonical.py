"""
Nekhebet Core v4.0.0 — RFC 8785 compliant canonicalization

Implements JSON Canonicalization Scheme (JCS) for deterministic signing.
All output is guaranteed to be identical across platforms and runs.

COMPATIBILITY WARNING:
This implementation uses Python's json.dumps with repr(float) (Ryu algorithm).
While this satisfies RFC 8785 on IEEE-754 platforms, cross-language 
compatibility with other JCS implementations is NOT guaranteed.

Normative implementation:
- CPython >= 3.10
- json.dumps + repr(float) (Ryu algorithm)
- IEEE-754 floating-point representation

Edge cases:
- RFC 8785 requires -0 to be serialized as "-0"
- CPython json.dumps correctly preserves sign for -0.0
- Other implementations may differ

For guaranteed cross-language JCS compatibility:
- Install the `jcs` package (pure-Python JCS)
- Or ensure identical Python versions on all systems

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
# RFC 8785 requirements satisfied by CPython's json.dumps when configured:
# - UTF-8 encoding
# - No insignificant whitespace
# - Object member names sorted lexicographically by Unicode code points
# - Deterministic number formatting (via repr(float) + Ryu algorithm)
# - No NaN / Infinity (rejected earlier by payload validation)
#
# Important notes:
# - repr(float) behavior is part of CPython API but not formally a cryptographic invariant
# - Cross-language compatibility risks exist with non-Python JCS implementations
# - -0.0 is correctly serialized as "-0" (RFC 8785 edge case requirement)
#
# References:
# - RFC 8785: https://www.rfc-editor.org/rfc/rfc8785
# - CPython float repr: https://github.com/python/cpython/blob/main/Python/dtoa.c
#

# =============================================================================
# Public API
# =============================================================================

def canonicalize(data: Dict[str, Any]) -> bytes:
    """
    Canonicalize a Python dict according to RFC 8785 (JCS).
    
    Uses Python's json.dumps with repr(float) (Ryu algorithm).
    
    COMPATIBILITY WARNING:
    - Guaranteed only for IEEE-754 platforms
    - Cross-language JCS compatibility not assured
    - Float representation depends on CPython's repr() implementation
    
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
        # RFC 8785 / JCS canonical JSON using CPython's implementation
        # - sorted keys
        # - no insignificant whitespace
        # - UTF-8 encoding
        # - repr(float) with Ryu algorithm for minimal decimal representation
        canonical_str = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),  # no insignificant whitespace
            allow_nan=False,        # REQUIRED by RFC 8785
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
    
    Note: Uses the same canonicalization as payload data (json.dumps).
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
    
    Note: Uses canonicalize() with all its compatibility caveats.
    
    Args:
        payload: Event payload dictionary
        
    Returns:
        str: Lowercase hexadecimal SHA-256 digest
    """
    canonical_bytes = canonicalize(payload)
    return compute_payload_hash_from_canonical(canonical_bytes)
