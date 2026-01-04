"""
Nekhebet Core v4.0.0 — Serialization
High-performance serialization/deserialization of SignedEnvelope.
Uses msgspec for speed and strict validation.

FIXES APPLIED:
- Added proper base64 encoding/decoding for bytes fields (signature, public_key)
- Replaced non-existent msgspec.base64_encode with standard base64
- Added dec_hook to Decoder for automatic base64 → bytes conversion
- Added strict validation in dec_hook (using validate=True where possible)
- Minor cleanups and error handling improvements
"""

from __future__ import annotations

import base64
import json
import msgspec
from typing import Final

from .types import SignedEnvelope


# =============================================================================
# Hooks for base64 handling
# =============================================================================

def _enc_hook(obj: any) -> any:
    """Encode bytes → base64 string for JSON compatibility."""
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(obj).decode("ascii")
    raise TypeError(f"Objects of type {type(obj)} are not serializable")


def _dec_hook(type_: type, obj: any) -> any:
    """Decode base64 string → bytes when target type is bytes."""
    if type_ is bytes:
        if not isinstance(obj, str):
            raise msgspec.ValidationError("bytes fields must be base64-encoded strings")
        try:
            # validate=True rejects invalid padding/length (Python 3.11+)
            return base64.b64decode(obj, validate=True)
        except Exception as e:
            raise msgspec.ValidationError(f"Invalid base64 encoding: {e}") from e
    # For all other types, return unchanged
    return obj


# =============================================================================
# Encoders/Decoders
# =============================================================================

# Compact binary JSON encoder with base64 support
ENVELOPE_ENCODER: Final[msgspec.json.Encoder] = msgspec.json.Encoder(enc_hook=_enc_hook)

# Strict decoder with base64 → bytes conversion and validation
ENVELOPE_DECODER: Final[msgspec.json.Decoder] = msgspec.json.Decoder(
    SignedEnvelope, dec_hook=_dec_hook
)


# =============================================================================
# Public API
# =============================================================================

def to_json_bytes(envelope: SignedEnvelope) -> bytes:
    """
    Serialize SignedEnvelope to compact JSON bytes.
    
    - bytes fields (signature, public_key) encoded as base64 strings
    - No pretty-printing, minimal size
    - Compatible with standard JSON parsers
    
    Args:
        envelope: Signed envelope to serialize
    
    Returns:
        bytes: Serialized envelope
    
    Raises:
        ValueError: If serialization fails
    """
    try:
        return ENVELOPE_ENCODER.encode(envelope)
    except msgspec.EncodeError as e:
        raise ValueError(f"Failed to serialize envelope: {e}") from e


def from_json_bytes(data: bytes) -> SignedEnvelope:
    """
    Deserialize bytes into validated SignedEnvelope.
    
    - Automatically decodes base64 for signature and public_key
    - Full structural validation via msgspec.Struct
    - Strict base64 validation
    - Raises on any malformation
    
    Args:
        data: Serialized envelope bytes
    
    Returns:
        SignedEnvelope: Deserialized and validated envelope
    
    Raises:
        ValueError: If deserialization or validation fails
    """
    try:
        return ENVELOPE_DECODER.decode(data)
    except (msgspec.DecodeError, msgspec.ValidationError) as e:
        raise ValueError(f"Invalid envelope data: {e}") from e


# =============================================================================
# Optional: human-readable variant (for debugging/logs)
# =============================================================================

def to_pretty_json_bytes(envelope: SignedEnvelope) -> bytes:
    """
    Serialize with indentation — for logs, debugging, audits.
    NOT SAFE for signing or hashing.
    
    Args:
        envelope: Signed envelope to serialize
    
    Returns:
        bytes: Pretty-printed JSON bytes
    """
    data = msgspec.to_builtins(envelope, enc_hook=_enc_hook)
    return json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")