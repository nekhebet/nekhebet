"""
Nekhebet Core v4.0.0 — canonical signed event system

Public API exports for Nekhebet Core.

WARNING:
- This module defines the PUBLIC API.
- Any changes to exports are breaking changes.
- Internal modules may be restructured, but exports must remain stable.
"""

from __future__ import annotations

# =============================================================================
# Core types and protocols
# =============================================================================
from .types import (
    # Constants
    CLOCK_SKEW_ALLOW,
    MAX_EXPIRES_SECONDS,
    MAX_SOURCE_LENGTH,
    MAX_KEY_ID_LENGTH,
    MAX_ABSOLUTE_PAYLOAD_SIZE,
    MAX_PAYLOAD_DEPTH,
    
    # Types
    Algorithm,
    CanonicalizationMode,
    VerificationCategory,
    
    # Envelope structures
    EnvelopeHeader,
    EnvelopeSignature,
    SignedEnvelope,
    UnsignedEnvelope,
    
    # Results & protocols
    VerificationResult,
    SigningContextProtocol,
    ReplayGuardProtocol,
    
    # Errors
    PayloadTooLargeError,
)

# =============================================================================
# Core functionality
# =============================================================================
from .envelope import create_envelope, add_signature
from .signing import sign_envelope, DefaultSigningContext
from .verification import verify_envelope
from .replay_guard import InMemoryReplayGuard
from .serialization import to_json_bytes, from_json_bytes, to_pretty_json_bytes

# =============================================================================
# Configuration and utilities
# =============================================================================
from .config import get_config, clear_config_cache
from .canonical import (
    canonicalize,
    canonicalize_header,
    compute_payload_hash,
    compute_payload_hash_from_canonical,
)
from .utils import (
    mask_sensitive_data,
    is_valid_key_id,
    is_valid_nonce,           
    is_iso8601_utc,
    estimate_payload_size,
    validate_payload_structure,
    b64_encode_bytes,
    b64_decode_str,
    RESERVED_PAYLOAD_FIELDS,
)

# =============================================================================
# Registry and metrics
# =============================================================================
from .registry import EVENT_REGISTRY, get_event_policy
from .metrics import metrics, record_signing, record_verification

# =============================================================================
# Public API definition
# =============================================================================
__all__ = [
    # Types and constants
    "CLOCK_SKEW_ALLOW",
    "MAX_EXPIRES_SECONDS",
    "MAX_SOURCE_LENGTH",
    "MAX_KEY_ID_LENGTH",
    "MAX_ABSOLUTE_PAYLOAD_SIZE",
    "MAX_PAYLOAD_DEPTH",
    "Algorithm",
    "CanonicalizationMode",
    "VerificationCategory",
    "EnvelopeHeader",
    "EnvelopeSignature",
    "SignedEnvelope",
    "UnsignedEnvelope",
    "VerificationResult",
    "SigningContextProtocol",
    "ReplayGuardProtocol",
    "PayloadTooLargeError",
    
    # Core functionality
    "create_envelope",
    "add_signature",
    "sign_envelope",
    "DefaultSigningContext",
    "verify_envelope",
    "InMemoryReplayGuard",
    "to_json_bytes",
    "from_json_bytes",
    "to_pretty_json_bytes",
    
    # Configuration and utilities
    "get_config",
    "clear_config_cache",
    "canonicalize",
    "canonicalize_header",
    "compute_payload_hash",
    "compute_payload_hash_from_canonical",
    "mask_sensitive_data",
    "is_valid_key_id",
    "is_valid_nonce",          
    "is_iso8601_utc",
    "estimate_payload_size",
    "validate_payload_structure",
    "b64_encode_bytes",
    "b64_decode_str",
    "RESERVED_PAYLOAD_FIELDS",
    
    # Registry and metrics
    "EVENT_REGISTRY",
    "get_event_policy",
    "metrics",
    "record_signing",
    "record_verification",
]

__version__ = "4.0.0"
__author__ = "Nekhebet Team"
__license__ = "MIT"
