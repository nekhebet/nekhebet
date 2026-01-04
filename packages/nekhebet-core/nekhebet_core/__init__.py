"""
Nekhebet Core v4.0.0 — Public package interface

High-performance, audit-ready, RFC 8785-compliant event envelope system.

Design principles:
- Only signed envelopes (no unsigned events)
- Deterministic canonicalization (RFC 8785)
- Strict security by default
- Explicit trust boundaries
"""

from __future__ import annotations

__version__ = "4.0.0"
__author__ = "Nekhebet Team"
__description__ = (
    "Signed Envelope event system with strict canonicalization and security"
)

# =============================================================================
# Core structures & protocols
# =============================================================================

from .types import (
    SignedEnvelope,
    EnvelopeHeader,
    VerificationResult,
    SigningContextProtocol,
    ReplayGuardProtocol,
    CLOCK_SKEW_ALLOW,
    MAX_EXPIRES_SECONDS,
)

# =============================================================================
# Creation & Signing
# =============================================================================

from .envelope import create_envelope, add_signature
from .signing import (
    sign_envelope,
    DefaultSigningContext,
    # load_signing_context_from_env remains a demo helper – not exposed by default
)

# =============================================================================
# Verification
# =============================================================================

from .verification import verify_envelope

# =============================================================================
# Serialization
# =============================================================================

from .serialization import (
    to_json_bytes,
    from_json_bytes,
    to_pretty_json_bytes,
)

# =============================================================================
# Configuration & Registry
# =============================================================================

from .config import get_config, clear_config_cache
from .registry import EVENT_REGISTRY, get_event_policy

# =============================================================================
# Utilities (selective export — only safe/public helpers)
# =============================================================================

from .utils import (
    mask_sensitive_data,
    is_valid_key_id,
    is_secure_nonce,
)

# =============================================================================
# Replay Guard (expose the improved in-memory implementation)
# =============================================================================

from .replay_guard import InMemoryReplayGuard

# =============================================================================
# Metrics (optional dependency, graceful degradation)
# =============================================================================

try:
    from .metrics import metrics, record_signing, record_verification
except ImportError:  # pragma: no cover
    metrics = None

    def record_signing(*args, **kwargs) -> None:  # type: ignore
        """No-op when metrics module is unavailable."""
        return None

    def record_verification(*args, **kwargs) -> None:  # type: ignore
        """No-op when metrics module is unavailable."""
        return None

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Package metadata
    "__version__",
    "__author__",
    "__description__",

    # Core types & protocols
    "SignedEnvelope",
    "EnvelopeHeader",
    "VerificationResult",
    "SigningContextProtocol",
    "ReplayGuardProtocol",
    "CLOCK_SKEW_ALLOW",
    "MAX_EXPIRES_SECONDS",

    # Core lifecycle
    "create_envelope",
    "add_signature",
    "sign_envelope",
    "verify_envelope",

    # Signing context
    "DefaultSigningContext",

    # Serialization
    "to_json_bytes",
    "from_json_bytes",
    "to_pretty_json_bytes",

    # Configuration & policy
    "get_config",
    "clear_config_cache",
    "EVENT_REGISTRY",
    "get_event_policy",

    # Utilities
    "mask_sensitive_data",
    "is_valid_key_id",
    "is_secure_nonce",

    # Replay guard
    "InMemoryReplayGuard",

    # Metrics (optional)
    "metrics",
    "record_signing",
    "record_verification",
]
