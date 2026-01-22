"""
Nekhebet Core v4.0.0 — Serialization

High-performance serialization/deserialization of SignedEnvelope.
Uses msgspec for speed and strict validation.

SECURITY NOTES:
- This module is part of the security boundary.
- Serialization must be deterministic and strict.
- Any relaxation here is a breaking security change.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Final

import msgspec

from .types import SignedEnvelope


# =============================================================================
# Hooks for base64 handling
# =============================================================================

def _enc_hook(obj: Any) -> Any:
    """
    Encode bytes → base64 ASCII string for JSON compatibility.
    """
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(obj).decode("ascii")
    raise TypeError(f"Objects of type {type(obj).__name__} are not serializable")


def _dec_hook(type_: type, obj: Any) -> Any:
    """
    Decode base64 ASCII string → bytes when target type is bytes.

    Uses strict validation to reject malformed or non-canonical encodings.
    """
    if type_ is bytes:
        if not isinstance(obj, str):
            raise msgspec.ValidationError(
                "bytes fields must be base64-encoded strings"
            )
        try:
            # validate=True rejects invalid padding / non-base64 input
            return base64.b64decode(obj, validate=True)
        except Exception as e:
            raise msgspec.ValidationError(
                f"Invalid base64 encoding: {e}"
            ) from e

    # All other types are handled by msgspec itself
    return obj


# =============================================================================
# Encoders / Decoders
# =============================================================================

# Compact JSON encoder with deterministic output and base64 support
ENVELOPE_ENCODER: Final[msgspec.json.Encoder] = msgspec.json.Encoder(
    enc_hook=_enc_hook
)

# Strict decoder with structural + base64 validation
ENVELOPE_DECODER: Final[msgspec.json.Decoder] = msgspec.json.Decoder(  # type: ignore[type-arg]
    SignedEnvelope,
    dec_hook=_dec_hook,
)


# =============================================================================
# Public API
# =============================================================================

def to_json_bytes(envelope: SignedEnvelope) -> bytes:
    """
    Serialize SignedEnvelope to compact JSON bytes.

    - bytes fields encoded as base64 ASCII strings
    - minimal size, no pretty-printing
    - SAFE for hashing, signing and storage

    Raises:
        ValueError: on serialization failure
    """
    try:
        return ENVELOPE_ENCODER.encode(envelope)
    except msgspec.EncodeError as e:
        raise ValueError(f"Failed to serialize envelope: {e}") from e


def from_json_bytes(data: bytes) -> SignedEnvelope:
    """
    Deserialize bytes into a fully validated SignedEnvelope.

    - strict structural validation via msgspec.Struct
    - strict base64 decoding for bytes fields
    - rejects any malformed or unexpected input

    Raises:
        ValueError: on deserialization or validation failure
    """
    try:
        return ENVELOPE_DECODER.decode(data)  # type: ignore[no-any-return]
    except (msgspec.DecodeError, msgspec.ValidationError) as e:
        raise ValueError(f"Invalid envelope data: {e}") from e
        
# =============================================================================
# Human-readable variant (DEBUG ONLY)
# =============================================================================

def to_pretty_json_bytes(envelope: SignedEnvelope) -> bytes:
    """
    Serialize envelope to pretty-printed JSON bytes.

    WARNING:
    - NOT deterministic
    - NOT SAFE for hashing or signing
    - Intended ONLY for logs, debugging and audits
    """
    data = msgspec.to_builtins(envelope, enc_hook=_enc_hook)
    return json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
