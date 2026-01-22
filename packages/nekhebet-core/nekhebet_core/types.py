"""
Nekhebet Core v4.0.0 — Core types and protocols

Defines all canonical data structures, protocols, constants and
security-related exceptions used across Nekhebet Core.

SECURITY NOTE:
This module defines the SHAPE of signed data.
Any incompatible change to the Struct definitions or field semantics
WILL break signature verification and invalidate existing envelopes.
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional, Protocol, runtime_checkable
from typing import TypedDict

import msgspec


# =============================================================================
# Global security constants
# =============================================================================

CLOCK_SKEW_ALLOW: int = 300              # seconds, 5 minutes
MAX_EXPIRES_SECONDS: int = 60 * 60 * 24  # 24 hours
MAX_SOURCE_LENGTH: int = 128
MAX_KEY_ID_LENGTH: int = 64
MAX_ABSOLUTE_PAYLOAD_SIZE: int = 1024 * 1024  # 1 MiB canonicalized

# Payload DoS protection
MAX_PAYLOAD_DEPTH: int = 16


# =============================================================================
# Supported algorithms and canonicalization modes
# =============================================================================

Algorithm = Literal["ed25519"]
CanonicalizationMode = Literal["rfc8785"]


# =============================================================================
# Verification failure categories (for metrics and auditing)
# =============================================================================

VerificationCategory = Literal[
    "structure_invalid",
    "hash_mismatch",
    "signature_invalid",
    "key_id_mismatch",
    "expired",
    "timestamp_future",
    "replay_detected",
    "nonce_insecure",
    "event_type_invalid",
    "unsupported_version",
    "payload_too_large",
]


# =============================================================================
# Core envelope structures
# =============================================================================

class EnvelopeHeader(msgspec.Struct, kw_only=True, frozen=True):
    """
    Canonical envelope header — the signed portion.
    ANY change to fields or their semantics INVALIDATES all existing signatures.
    """
    id: str                          # UUID as string
    type: str                        # Registered event type
    version: str = "4.0.0"
    source: str
    issued_at: str                   # ISO8601 UTC with 'Z'
    expires_at: Optional[str] = None # ISO8601 UTC with 'Z' or None
    nonce: str
    key_id: str
    algorithm: Algorithm = "ed25519"
    canonicalization: CanonicalizationMode = "rfc8785"
    payload_hash: str                # SHA-256 hex (lowercase, 64 characters)
    context: Optional[Dict[str, Any]] = None
    extensions: Optional[Dict[str, Any]] = None


class EnvelopeSignature(msgspec.Struct, kw_only=True, frozen=True):
    """
    Cryptographic signature and public key container.
    """
    signature: bytes   # Raw 64-byte Ed25519 signature
    public_key: bytes  # Raw 32-byte Ed25519 public key


class SignedEnvelope(msgspec.Struct, kw_only=True, frozen=True):
    """
    Complete signed envelope — the only structure allowed to cross trust boundaries.
    """
    header: EnvelopeHeader
    payload: Dict[str, Any]
    signature: EnvelopeSignature


# =============================================================================
# Internal unsigned envelope (never exposed externally)
# =============================================================================

class UnsignedEnvelope(TypedDict):
    """
    Temporary internal representation before signing.
    MUST NOT be serialized or transmitted.
    """
    header: EnvelopeHeader
    payload: Dict[str, Any]


# =============================================================================
# Verification result — now a frozen Struct matching actual return values
# =============================================================================

class VerificationResult(msgspec.Struct, kw_only=True, frozen=True):
    """
    Result of envelope verification.

    Immutable struct reflecting all fields returned by verify_envelope().
    """
    valid: bool
    reason: str
    category: Optional[VerificationCategory] = None
    details: Dict[str, Any] = msgspec.field(default_factory=dict)
    verification_time_ms: float
    boundary: str = "signed"


# =============================================================================
# Protocols — match existing implementations
# =============================================================================

@runtime_checkable
class SigningContextProtocol(Protocol):
    """
    Interface for signing operations.
    Canonical contract for all signing backends.
    """
    key_id: str

    def sign(self, data: bytes) -> bytes:
        """Sign canonical header bytes → raw signature."""
        ...

    @property
    def public_key_bytes(self) -> bytes:
        """Return raw Ed25519 public key bytes."""
        ...


@runtime_checkable
class ReplayGuardProtocol(Protocol):
    """
    Interface for stateful replay protection.
    """
    def check_and_store(
        self,
        key_id: str,
        nonce: str,
        issued_at: str,
    ) -> bool:
        """
        Atomically check and store (key_id, nonce).
        Returns True if new, False if replay detected.
        """
        ...


# =============================================================================
# Security exceptions
# =============================================================================

class PayloadTooLargeError(ValueError):
    """Raised when canonicalized payload exceeds absolute size limit."""
    pass


# =============================================================================
# Public exports
# =============================================================================

__all__ = [
    # Constants
    "CLOCK_SKEW_ALLOW",
    "MAX_EXPIRES_SECONDS",
    "MAX_SOURCE_LENGTH",
    "MAX_KEY_ID_LENGTH",
    "MAX_ABSOLUTE_PAYLOAD_SIZE",
    "MAX_PAYLOAD_DEPTH",

    # Types
    "Algorithm",
    "CanonicalizationMode",
    "VerificationCategory",

    # Envelope structures
    "EnvelopeHeader",
    "EnvelopeSignature",
    "SignedEnvelope",
    "UnsignedEnvelope",

    # Results & protocols
    "VerificationResult",
    "SigningContextProtocol",
    "ReplayGuardProtocol",

    # Errors
    "PayloadTooLargeError",
]