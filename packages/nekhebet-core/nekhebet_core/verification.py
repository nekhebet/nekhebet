"""
Nekhebet Core v4.0.0 — Envelope verification

Strict verification of signed envelopes with auditable results.

SECURITY INVARIANTS:
- Verification MUST use the SAME canonicalization path as signing.
- Verification MUST NOT trust any data created outside this boundary.
- Replay protection MUST be applied only to temporally valid envelopes.
- All inputs are treated as fully untrusted — zero assumptions.
"""

from __future__ import annotations

import time
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)  # type: ignore[import-not-found]


from .types import (
    SignedEnvelope,
    VerificationResult,
    VerificationCategory,
    ReplayGuardProtocol,
    CLOCK_SKEW_ALLOW,
    MAX_SOURCE_LENGTH,
    MAX_ABSOLUTE_PAYLOAD_SIZE,
)
from .canonical import (
    canonicalize,
    canonicalize_header,
    compute_payload_hash_from_canonical,
)
from .utils import (
    mask_sensitive_data,
    is_iso8601_utc,
    is_secure_nonce,
    estimate_payload_size,
)
from .registry import get_event_policy
from .config import get_config


# =============================================================================
# Internal constants (audited)
# =============================================================================
_PAYLOAD_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_NONCE_LENGTH = 256  # Upper bound — prevents DoS via enormous strings


# =============================================================================
# Result helpers (single source of truth for timing)
# =============================================================================
def _error_result(
    category: VerificationCategory,
    reason: str,
    start_time: float,
    details: Optional[Dict[str, Any]] = None,
) -> VerificationResult:
    """Construct a failed VerificationResult."""
    return VerificationResult(
        valid=False,
        reason=reason,
        category=category,
        details=details or {},
        verification_time_ms=(time.time() - start_time) * 1000,
        boundary="signed",
    )


def _success_result(
    details: Dict[str, Any],
    start_time: float,
) -> VerificationResult:
    """Construct a successful VerificationResult."""
    return VerificationResult(
        valid=True,
        reason="Envelope verified successfully",
        category=None,
        details=details,
        verification_time_ms=(time.time() - start_time) * 1000,
        boundary="signed",
    )


# =============================================================================
# Public API
# =============================================================================
def verify_envelope(
    envelope: SignedEnvelope,
    *,
    replay_guard: Optional[ReplayGuardProtocol] = None,
    current_time: Optional[datetime] = None,
    strict: bool = True,
) -> VerificationResult:
    """
    Verify a signed envelope.

    Comprehensive zero-trust verification pipeline:
    1. Event type policy
    2. Protocol invariants (version, algorithm, canonicalization)
    3. Structural validation (lengths, formats)
    4. Nonce security (policy-driven)
    5. Timestamp validation (issued_at + expires_at)
    6. Replay protection (only for temporally valid envelopes)
    7. Signature verification
    8. Payload DoS protection (estimate)
    9. Payload canonicalization + hash verification

    All checks are defensive and ordered by cost (cheap first).

    SECURITY NOTES:
    - This function defines the primary trust boundary for incoming envelopes.
    - No data from creation path is trusted.
    - Failures are categorized for metrics and audit.
    """
    start = time.time()
    now = current_time or datetime.now(timezone.utc)

    header = envelope.header
    payload = envelope.payload
    signature = envelope.signature

    details: Dict[str, Any] = {
        "envelope_id": header.id,
        "event_type": header.type,
        "source": header.source,
        "issued_at": header.issued_at,
        "expires_at": header.expires_at,
        "key_id": mask_sensitive_data(header.key_id),
    }

    # ------------------------------------------------------------------
    # 1. Event type policy
    # ------------------------------------------------------------------
    try:
        policy = get_event_policy(header.type)
    except ValueError:
        return _error_result(
            "event_type_invalid",
            "Event type is not registered",
            start,
            {"event_type": header.type},
        )

    # ------------------------------------------------------------------
    # 2. Protocol invariants
    # ------------------------------------------------------------------
    if header.version != "4.0.0":
        return _error_result(
            "unsupported_version",
            "Unsupported envelope version",
            start,
            {"version": header.version},
        )
    if header.algorithm != "ed25519":
        return _error_result(
            "unsupported_version",
            "Unsupported signature algorithm",
            start,
            {"algorithm": header.algorithm},
        )
    if header.canonicalization != "rfc8785":
        return _error_result(
            "unsupported_version",
            "Unsupported canonicalization mode",
            start,
            {"canonicalization": header.canonicalization},
        )

    # ------------------------------------------------------------------
    # 3. Structural validation (cheap checks first)
    # ------------------------------------------------------------------
    if len(header.source) > MAX_SOURCE_LENGTH:
        return _error_result(
            "structure_invalid",
            "Source exceeds maximum allowed length",
            start,
            {"max_length": MAX_SOURCE_LENGTH},
        )

    if (
        not isinstance(header.nonce, str)
        or not header.nonce
        or len(header.nonce) > _MAX_NONCE_LENGTH
    ):
        return _error_result(
            "structure_invalid",
            "Invalid nonce: empty or exceeds maximum length",
            start,
            {"max_length": _MAX_NONCE_LENGTH},
        )

    if len(signature.signature) != 64 or len(signature.public_key) != 32:
        return _error_result(
            "structure_invalid",
            "Invalid signature or public key length",
            start,
        )

    if not _PAYLOAD_HASH_RE.fullmatch(header.payload_hash):
        return _error_result(
            "structure_invalid",
            "Invalid payload_hash format (must be 64 lowercase hex chars)",
            start,
        )

    # ------------------------------------------------------------------
    # 4. Nonce security (strict mode, policy-driven)
    # ------------------------------------------------------------------
    if strict:
        config = get_config()
        require_secure = (
            policy.get("require_secure_nonce", True)
            or config.require_secure_nonce_global
        )
        if require_secure and not is_secure_nonce(header.nonce):
            return _error_result(
                "nonce_insecure",
                "Nonce does not meet security requirements",
                start,
            )

    # ------------------------------------------------------------------
    # 5. Timestamp validation (authoritative ordering)
    # ------------------------------------------------------------------
    if not is_iso8601_utc(header.issued_at):
        return _error_result(
            "structure_invalid",
            "Invalid issued_at format",
            start,
        )

    issued_dt = datetime.fromisoformat(header.issued_at.replace("Z", "+00:00"))
    if issued_dt > now + timedelta(seconds=CLOCK_SKEW_ALLOW):
        return _error_result(
            "timestamp_future",
            "Envelope issued in the future (beyond clock skew tolerance)",
            start,
        )

    expires_dt: Optional[datetime] = None
    if header.expires_at:
        if not is_iso8601_utc(header.expires_at):
            return _error_result(
                "structure_invalid",
                "Invalid expires_at format",
                start,
            )
        expires_dt = datetime.fromisoformat(header.expires_at.replace("Z", "+00:00"))
        if expires_dt < issued_dt:
            return _error_result(
                "structure_invalid",
                "expires_at is earlier than issued_at",
                start,
            )
        if expires_dt < now:
            return _error_result(
                "expired",
                "Envelope has expired",
                start,
            )

    # ------------------------------------------------------------------
    # 6. Replay protection (ONLY after full temporal validity)
    # ------------------------------------------------------------------
    if replay_guard:
        accepted = replay_guard.check_and_store(
            header.key_id,
            header.nonce,
            header.issued_at,
        )
        if not accepted:
            try:
                from .metrics import metrics
                metrics.record_replay_detected()
            except ImportError:
                pass
            return _error_result(
                "replay_detected",
                "Replay attack detected or guard rejection",
                start,
            )

    # ------------------------------------------------------------------
    # 7. Signature verification (cryptographic core)
    # ------------------------------------------------------------------
    header_bytes = canonicalize_header(header)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(signature.public_key)
        public_key.verify(signature.signature, header_bytes)
    except Exception:
        return _error_result(
            "signature_invalid",
            "Signature verification failed",
            start,
        )

    # ------------------------------------------------------------------
    # 8. Payload DoS protection (defensive estimate)
    # ------------------------------------------------------------------
    try:
        estimated_size = estimate_payload_size(payload)
    except ValueError as e:
        return _error_result(
            "payload_too_large",
            f"Invalid payload structure: {e}",
            start,
        )

    if estimated_size > MAX_ABSOLUTE_PAYLOAD_SIZE:
        return _error_result(
            "payload_too_large",
            "Estimated payload size exceeds absolute limit",
            start,
            {"estimated_size": estimated_size},
        )

    # ------------------------------------------------------------------
    # 9. Payload canonicalization + hash verification (authoritative)
    # ------------------------------------------------------------------
    try:
        canonical_payload = canonicalize(payload)
    except Exception as e:
        return _error_result(
            "structure_invalid",
            f"Payload canonicalization failed: {e}",
            start,
        )

    computed_hash = compute_payload_hash_from_canonical(canonical_payload)
    if computed_hash != header.payload_hash:
        return _error_result(
            "hash_mismatch",
            "Payload hash mismatch",
            start,
        )

    # ------------------------------------------------------------------
    # 10. Success — record metric
    # ------------------------------------------------------------------
    try:
        from .metrics import record_verification

        record_verification(
            event_type=header.type,
            start_time=start,
            result={"valid": True, "category": None},
        )
    except ImportError:
        pass

    return _success_result(details, start)


# =============================================================================
# Internal fast-path (NOT PUBLIC — for trusted internal use only)
# =============================================================================
def _fast_verify_without_replay_and_nonce(envelope: SignedEnvelope) -> bool:
    """
    INTERNAL FAST-PATH VERIFICATION — SECURITY FOOTGUN.

    Disables:
      - Replay protection
      - Strict nonce strength checks

    MUST ONLY be used in fully trusted internal systems where replay/nonce
    are handled elsewhere.

    All other checks remain enabled.
    """
    try:
        return verify_envelope(
            envelope,
            replay_guard=None,
            strict=False,
        ).valid
    except Exception:
        return False
