"""
Nekhebet Core v4.0.0 — Utility functions

Validation helpers, security checks and DoS protection utilities.

SECURITY NOTES:
- This module is part of the security boundary.
- Functions here must be deterministic and side-effect free.
- Any relaxation of validation rules is a breaking security change.
- All functions assume untrusted input and must reject malformed data early.
"""

from __future__ import annotations

import base64
import math
import re
from datetime import datetime
from typing import Any, Dict, Optional, Set

from .types import (
    MAX_PAYLOAD_DEPTH,
    MAX_KEY_ID_LENGTH,
)

# =============================================================================
# Reserved payload fields
# =============================================================================
#
# These fields are managed exclusively by the envelope/header layer
# and MUST NOT appear inside the payload.
#
# Presence of any of these fields inside payload is a hard validation error.
#

RESERVED_PAYLOAD_FIELDS: Set[str] = {
    # Envelope-level structure
    "header",
    "signature",
    "payload_hash",

    # Header fields
    "id",
    "type",
    "version",
    "source",
    "issued_at",
    "expires_at",
    "nonce",
    "key_id",
    "algorithm",
    "canonicalization",
    "context",
    "extensions",
}

# =============================================================================
# Regular expressions for validation
# =============================================================================

_KEY_ID_RE = re.compile(rf"^[a-zA-Z0-9_-]{{1,{MAX_KEY_ID_LENGTH}}}$")
_ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?Z$"
)

# Nonce validation regexes
# Nekhebet uses hexadecimal nonce format exclusively
_NONCE_HEX_RE = re.compile(r"^[0-9a-f]{32,100}$")  # 32-100 hex characters

# =============================================================================
# Sensitive data masking
# =============================================================================

def mask_sensitive_data(data: Optional[str], visible_chars: int = 4) -> str:
    """
    Mask sensitive string data (key_id, nonce, etc.) for logs.

    Args:
        data: Sensitive string
        visible_chars: Number of characters kept visible at both ends

    Returns:
        Masked string safe for logging
    """
    if not data:
        return "***"

    data_len = len(data)
    if data_len <= visible_chars * 2:
        return "***"

    start = data[:visible_chars]
    end = data[-visible_chars:] if visible_chars > 0 else ""
    return f"{start}***{end}"


# =============================================================================
# Basic validators
# =============================================================================

def is_valid_key_id(key_id: str) -> bool:
    """
    Validate key_id format and length.

    key_id must:
    - be non-empty
    - contain only [A-Za-z0-9_-]
    - not exceed MAX_KEY_ID_LENGTH
    """
    if not isinstance(key_id, str):
        return False
    return bool(_KEY_ID_RE.fullmatch(key_id))


def is_valid_nonce(nonce: str) -> bool:
    """
    Validate nonce structure according to Nekhebet specification.

    Nekhebet uses hexadecimal nonce format exclusively.
    
    Requirements:
    - Hexadecimal characters [0-9a-f] (lowercase)
    - Minimum 32 characters (128 bits)
    - Maximum 100 characters (DoS protection)
    
    Security Notes:
    - This validates FORMAT only
    - Does NOT validate cryptographic quality
    - Does NOT attempt entropy estimation
    - Replay protection ensures uniqueness, not randomness
    """
    if not isinstance(nonce, str):
        return False
    
    # Note: We use the same regex for both validation and DoS protection
    # The regex enforces both format and length limits
    return bool(_NONCE_HEX_RE.fullmatch(nonce))


def is_iso8601_utc(timestamp: str) -> bool:
    """
    Validate strict ISO-8601 UTC timestamp with 'Z' suffix.

    Accepted format: YYYY-MM-DDTHH:MM:SS[.fraction]Z
    Rejects offsets, missing Z, malformed components.
    """
    if not isinstance(timestamp, str):
        return False
    if not _ISO8601_RE.match(timestamp):
        return False
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


# =============================================================================
# Payload protection against DoS and structural attacks
# =============================================================================

def estimate_payload_size(obj: Any, depth: int = 0) -> int:
    """
    Conservative estimation of JSON payload size without full serialization.

    Used as early DoS protection:
    - limits nesting depth
    - limits approximate memory cost
    - rejects non-JSON-serializable types early

    Args:
        obj: Object to estimate
        depth: Current recursion depth

    Returns:
        Estimated size in bytes

    Raises:
        ValueError: If nesting depth exceeds limit or unsupported/non-finite types found
    """
    if depth > MAX_PAYLOAD_DEPTH:
        raise ValueError(
            f"Payload nesting depth exceeds limit of {MAX_PAYLOAD_DEPTH}"
        )

    if isinstance(obj, dict):
        size = 2  # {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("Dictionary keys must be strings")
            size += len(k) + 4 + estimate_payload_size(v, depth + 1) + 1
        return max(size - 1, 2)

    if isinstance(obj, list):
        size = 2  # []
        for v in obj:
            size += estimate_payload_size(v, depth + 1) + 1
        return max(size - 1, 2)

    if isinstance(obj, str):
        return len(obj) + 2

    if isinstance(obj, (int, bool)):
        return len(str(obj))

    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("Non-finite float values (NaN, Inf) are not allowed in payload")
        return len(str(obj))

    if obj is None:
        return 4

    raise ValueError(f"Unsupported type in payload: {type(obj).__name__}")


def validate_payload_structure(payload: Dict[str, Any]) -> None:
    """
    Validate payload structure for security constraints.

    Enforces:
    - payload is a dict
    - no reserved envelope/header fields
    - bounded nesting depth (via estimate_payload_size)

    This function is intentionally minimal — canonicalize() is the final arbiter.

    Raises:
        ValueError: On any validation failure
    """
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a dictionary")

    reserved = RESERVED_PAYLOAD_FIELDS.intersection(payload.keys())
    if reserved:
        raise ValueError(
            f"Payload contains reserved fields: {sorted(reserved)}. "
            "These fields are managed by the envelope and are not allowed "
            "inside payload."
        )

    try:
        estimate_payload_size(payload)
    except ValueError as e:
        raise ValueError(f"Invalid payload structure: {e}") from e


# =============================================================================
# Base64 helpers (strict mode)
# =============================================================================

def b64_encode_bytes(data: bytes) -> str:
    """
    Encode bytes to strict base64 ASCII string (no padding issues).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("b64_encode_bytes expects bytes")
    return base64.b64encode(data).decode("ascii")


def b64_decode_str(data: str) -> bytes:
    """
    Decode strict base64 ASCII string to bytes.

    Uses validate=True to reject malformed/invalid padding input.
    """
    if not isinstance(data, str):
        raise TypeError("b64_decode_str expects string")
    try:
        return base64.b64decode(data, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {e}") from e


# =============================================================================
# Public exports (explicit — no accidental leakage)
# =============================================================================

__all__ = [
    "RESERVED_PAYLOAD_FIELDS",
    "mask_sensitive_data",
    "is_valid_key_id",
    "is_valid_nonce",
    "is_iso8601_utc",
    "estimate_payload_size",
    "validate_payload_structure",
    "b64_encode_bytes",
    "b64_decode_str",
]
