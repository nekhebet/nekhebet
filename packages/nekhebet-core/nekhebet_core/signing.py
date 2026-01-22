"""
Nekhebet Core v4.0.0 — Envelope signing

Signs the canonicalized envelope header using Ed25519.

SECURITY INVARIANT:
Signing and verification MUST use IDENTICAL canonicalization logic.
"""

from __future__ import annotations

import time
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
) 

from cryptography.hazmat.primitives import serialization 


from .types import (
    SignedEnvelope,
    SigningContextProtocol,
    UnsignedEnvelope,
)
from .canonical import canonicalize_header
from .envelope import add_signature

log = logging.getLogger(__name__)


# =============================================================================
# Default signing context
# =============================================================================

class DefaultSigningContext(SigningContextProtocol):
    """
    Default signing context using Ed25519.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        key_id: str,
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.key_id = key_id

        self._public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
            return True
        except Exception:
            return False

    def verify_with_key_id(
        self,
        data: bytes,
        signature: bytes,
        public_key: bytes,
        key_id: str,
    ) -> bool:
        if key_id != self.key_id:
            return False
        return self.verify(data, signature, public_key)


# =============================================================================
# Public API
# =============================================================================

def sign_envelope(
    unsigned_envelope: UnsignedEnvelope,
    signing_context: SigningContextProtocol,
) -> SignedEnvelope:
    """
    Sign an unsigned envelope.
    """
    start_time = time.time()
    header = unsigned_envelope["header"]

    if signing_context.key_id != header.key_id:
        raise ValueError(
            "Signing context key_id does not match envelope key_id"
        )

    header_bytes = canonicalize_header(header)
    signature_bytes = signing_context.sign(header_bytes)

    public_key_bytes = signing_context.public_key_bytes

    try:
        from .metrics import record_signing
        record_signing(header.type, start_time)
    except ImportError:
        pass

    return add_signature(
        unsigned=unsigned_envelope,
        signature=signature_bytes,
        public_key=public_key_bytes,
    )
