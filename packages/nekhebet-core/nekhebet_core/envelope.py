"""
Nekhebet Core v4.0.0 — Envelope creation and validation

Creates unsigned envelopes with full deterministic security validation.

SECURITY BOUNDARY (CRITICAL):
- This module defines the ONLY trusted path for creating new envelopes.
- Verification MUST NOT trust envelopes created here (zero-trust model).
- All checks performed here are intentionally duplicated in verify_envelope()
  for defense-in-depth at trust boundaries.
- Envelopes returned by create_envelope() are guaranteed safe to sign,
  but MUST undergo full verification before acceptance.

DO NOT assume creation-time validation substitutes for verification.
"""

from __future__ import annotations

import uuid
import secrets
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .types import SignedEnvelope

from .types import (
    EnvelopeHeader,
    UnsignedEnvelope,
    MAX_EXPIRES_SECONDS,
    MAX_SOURCE_LENGTH,
    MAX_ABSOLUTE_PAYLOAD_SIZE,
    PayloadTooLargeError,
)
from .utils import (
    estimate_payload_size,
    validate_payload_structure,
    is_valid_nonce,
    is_iso8601_utc,
    is_valid_key_id,
)
from .config import get_config
from .registry import get_event_policy
from .canonical import (
    canonicalize,
    compute_payload_hash_from_canonical,
)

# ------------------------------------------------------------------------------
# Module logger
# ------------------------------------------------------------------------------
log = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Hard security constants (audited limits)
# ------------------------------------------------------------------------------
MAX_EVENT_TYPE_LENGTH: int = 64          # DoS protection: indexes, metrics, logs
MAX_HEADER_DICT_CANONICAL_SIZE: int = 64 * 1024  # 64 KiB — header DoS protection
_PAYLOAD_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------
def create_envelope(
    *,
    event_type: str,
    payload: Dict[str, Any],
    source: str,
    key_id: str,
    nonce: Optional[str] = None,
    expires_in: Optional[int] = None,
    context: Optional[Dict[str, Any]] = None,
    extensions: Optional[Dict[str, Any]] = None,
    issued_at: Optional[str] = None,  # For testing / deterministic behavior
) -> UnsignedEnvelope:
    """
    Create a validated unsigned envelope ready for signing.

    Comprehensive validation pipeline:
    1. event_type: type + length + policy lookup
    2. source / key_id: format + length
    3. payload: structure → estimated size → canonical → hash
    4. context / extensions: structure + canonical size limits
    5. nonce: secure generation or structural validation
    6. timestamps: format + expiration bounds (per-policy)

    Nonce Security Model:
    - When nonce=None: cryptographically secure random nonce generated automatically
    - When nonce provided: only structural validation (format, length)
    - Cryptographic quality of user-provided nonce is NOT verified
    - Responsibility for nonce security lies with the caller
    - For production use, always use nonce=None (auto-generation)

    Guarantees (if no exception raised):
    - Structurally valid and policy-compliant
    - All DoS vectors bounded
    - payload_hash computed over authoritative canonical form
    - Safe to sign (signature will match verification path)

    Raises:
        ValueError: Validation/policy failure
        PayloadTooLargeError: Canonical payload exceeds absolute limit
    """
    config = get_config()

    # ------------------------------------------------------------------
    # 1. event_type validation (untrusted input — always validate)
    # ------------------------------------------------------------------
    if not isinstance(event_type, str):
        raise ValueError("event_type must be a string")
    if len(event_type) > MAX_EVENT_TYPE_LENGTH:
        raise ValueError(
            f"event_type exceeds maximum length of {MAX_EVENT_TYPE_LENGTH} characters"
        )

    policy = get_event_policy(event_type)
    event_max_expires = policy.get("max_expires_seconds", MAX_EXPIRES_SECONDS)

    require_secure_nonce = (
        policy.get("require_secure_nonce", True)
        or config.require_secure_nonce_global
    )

    # ------------------------------------------------------------------
    # 2. Basic field validation (cheap checks first)
    # ------------------------------------------------------------------
    if not isinstance(source, str):
        raise ValueError("source must be a string")
    if len(source) > MAX_SOURCE_LENGTH:
        raise ValueError(
            f"source exceeds maximum length of {MAX_SOURCE_LENGTH} characters"
        )
    if not is_valid_key_id(key_id):
        raise ValueError("Invalid key_id format")

    # ------------------------------------------------------------------
    # 3. Payload validation pipeline (structure → estimate → canonical → hash)
    # ------------------------------------------------------------------
    validate_payload_structure(payload)

    # Fast estimated size check — policy-aware early rejection
    try:
        estimated_size = estimate_payload_size(payload)
    except ValueError as e:
        raise ValueError(f"Invalid payload structure: {e}") from e

    max_allowed_estimated = min(
        int(config.base_payload_size * policy.get("max_payload_multiplier", 1.0)),
        MAX_ABSOLUTE_PAYLOAD_SIZE,
    )
    if estimated_size > max_allowed_estimated:
        raise ValueError(
            f"Estimated payload size {estimated_size} bytes exceeds "
            f"policy limit of {max_allowed_estimated} bytes for event_type '{event_type}'"
        )

    # Authoritative canonicalization
    canonical_payload = canonicalize(payload)
    canonical_size = len(canonical_payload)

    if canonical_size > MAX_ABSOLUTE_PAYLOAD_SIZE:
        raise PayloadTooLargeError(
            f"Canonical payload size {canonical_size} bytes exceeds "
            f"absolute limit of {MAX_ABSOLUTE_PAYLOAD_SIZE} bytes"
        )

    payload_hash = compute_payload_hash_from_canonical(canonical_payload)

    # Internal invariant check — should never fail
    if not _PAYLOAD_HASH_RE.fullmatch(payload_hash):
        raise RuntimeError(
            f"INTERNAL INVARIANT VIOLATION: computed payload_hash '{payload_hash[:16]}...' "
            f"has invalid format (length={len(payload_hash)})"
        )

    # ------------------------------------------------------------------
    # 4. Header fields: context & extensions (DoS protection)
    # ------------------------------------------------------------------
    if context is not None:
        validate_payload_structure(context)
        canonical_context = canonicalize(context)
        if len(canonical_context) > MAX_HEADER_DICT_CANONICAL_SIZE:
            raise ValueError(
                f"context canonical size {len(canonical_context)} bytes exceeds "
                f"limit of {MAX_HEADER_DICT_CANONICAL_SIZE} bytes"
            )

    if extensions is not None:
        validate_payload_structure(extensions)
        canonical_extensions = canonicalize(extensions)
        if len(canonical_extensions) > MAX_HEADER_DICT_CANONICAL_SIZE:
            raise ValueError(
                f"extensions canonical size {len(canonical_extensions)} bytes exceeds "
                f"limit of {MAX_HEADER_DICT_CANONICAL_SIZE} bytes"
            )

    # ------------------------------------------------------------------
    # 5. Nonce handling (SECURITY CRITICAL SECTION)
    # ------------------------------------------------------------------
    if nonce is None:
        # Secure by default: generate cryptographically secure random nonce
        nonce = secrets.token_hex(32)  # 256-bit cryptographically secure
        log.debug(
            "Auto-generated cryptographically secure nonce for event_type '%s'",
            event_type
        )
    else:
        # User-provided nonce: validate structure only
        if not is_valid_nonce(nonce):
            raise ValueError("Invalid nonce format")
        
        # Security advisory for user-provided nonces in secure contexts
        if require_secure_nonce:
            log.warning(
                "User-provided nonce used for secure event_type '%s'. "
                "For production security, use nonce=None (auto-generation). "
                "Responsibility for nonce cryptographic quality lies with caller.",
                event_type
            )
        
        # Note: We do NOT validate cryptographic quality of user-provided nonce
        # Replay protection ensures uniqueness, not randomness quality

    # ------------------------------------------------------------------
    # 6. Timestamp handling
    # ------------------------------------------------------------------
    if issued_at is None:
        issued_at_dt = datetime.now(timezone.utc)
        issued_at_str = issued_at_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    else:
        if not is_iso8601_utc(issued_at):
            raise ValueError("issued_at must be valid ISO8601 UTC with 'Z' suffix")
        issued_at_str = issued_at

    expires_at_str: Optional[str] = None
    if expires_in is not None:
        if expires_in <= 0:
            raise ValueError("expires_in must be a positive integer")
        if expires_in > event_max_expires:
            raise ValueError(
                f"expires_in={expires_in}s exceeds policy limit of {event_max_expires}s "
                f"for event_type '{event_type}' (global fallback: {MAX_EXPIRES_SECONDS}s)"
            )
        issued_dt = datetime.fromisoformat(issued_at_str.replace("Z", "+00:00"))
        expires_dt = issued_dt + timedelta(seconds=expires_in)
        expires_at_str = expires_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    # ------------------------------------------------------------------
    # 7. Construct immutable header
    # ------------------------------------------------------------------
    header = EnvelopeHeader(
        id=str(uuid.uuid4()),  # Non-security-critical identifier (collision-resistant only)
        type=event_type,
        source=source,
        issued_at=issued_at_str,
        expires_at=expires_at_str,
        nonce=nonce,
        key_id=key_id,
        payload_hash=payload_hash,
        context=context,
        extensions=extensions,
    )

    return {"header": header, "payload": payload}


# ------------------------------------------------------------------------------
# Signature attachment (minimal validation — trust higher-level wrapper)
# ------------------------------------------------------------------------------
def add_signature(
    unsigned: UnsignedEnvelope,
    signature: bytes,
    public_key: bytes,
) -> "SignedEnvelope":
    """
    Attach raw signature and public key to an unsigned envelope.

    SECURITY CRITICAL:
    - Performs NO cryptographic or structural validation.
    - Assumes:
        * unsigned came from create_envelope()
        * signature is valid Ed25519 over canonical header
        * public_key matches the signing key_id
    - This function exists primarily to avoid circular imports in sign_envelope().
    - Misuse WILL produce envelopes that fail verification.
    - Always prefer sign_envelope() over direct use.

    Basic type guard only — not a security boundary.
    """
    from .types import SignedEnvelope, EnvelopeSignature  # Avoid circular import

    if not isinstance(unsigned, dict) or "header" not in unsigned or "payload" not in unsigned:
        raise TypeError("unsigned must be a dict returned by create_envelope()")

    return SignedEnvelope(
        header=unsigned["header"],
        payload=unsigned["payload"],
        signature=EnvelopeSignature(
            signature=signature,
            public_key=public_key,
        ),
    )
