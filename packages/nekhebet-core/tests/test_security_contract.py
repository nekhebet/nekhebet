"""
Nekhebet Core — Security Contract Test

This test validates the full security contract:
- creation → signing → verification
- tampering rejection
- replay protection
- key binding
- canonicalization determinism

This is NOT a test suite.
This is a cryptographic contract.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nekhebet_core import (
    create_envelope,
    sign_envelope,
    verify_envelope,
    DefaultSigningContext,
)
from nekhebet_core.replay_guard import InMemoryReplayGuard
from nekhebet_core.types import SignedEnvelope, EnvelopeSignature


EVENT_TYPE = "omen.observed"
SOURCE = "security-test"
KEY_ID = "test-key"


def test_security_contract() -> None:
    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    ctx = DefaultSigningContext(
        private_key=priv,
        public_key=pub,
        key_id=KEY_ID,
    )

    payload = {"msg": "contract", "value": 42}
    guard = InMemoryReplayGuard()

    # ------------------------------------------------------------------
    # 1. Happy path
    # ------------------------------------------------------------------
    env = create_envelope(
        event_type=EVENT_TYPE,
        payload=payload,
        source=SOURCE,
        key_id=KEY_ID,
    )

    signed = sign_envelope(env, ctx)
    res = verify_envelope(signed, replay_guard=guard, strict=True)

    assert res.valid, "happy path must verify"

    # ------------------------------------------------------------------
    # 2. Replay must be rejected
    # ------------------------------------------------------------------
    res_replay = verify_envelope(signed, replay_guard=guard, strict=True)
    assert not res_replay.valid
    assert res_replay.category == "replay_detected"

    # ------------------------------------------------------------------
    # 3. Payload tampering must be detected
    # ------------------------------------------------------------------
    tampered = SignedEnvelope(
        header=signed.header,
        payload={"msg": "evil"},
        signature=signed.signature,
    )

    guard2 = InMemoryReplayGuard()
    res_tampered = verify_envelope(tampered, replay_guard=guard2, strict=True)

    assert not res_tampered.valid
    assert res_tampered.category == "hash_mismatch"

    # ------------------------------------------------------------------
    # 4. Signature must be bound to key
    # ------------------------------------------------------------------
    wrong_key = Ed25519PrivateKey.generate().public_key()
    forged_sig = EnvelopeSignature(
        signature=signed.signature.signature,
        public_key=wrong_key.public_bytes_raw(),
    )

    forged = SignedEnvelope(
        header=signed.header,
        payload=signed.payload,
        signature=forged_sig,
    )

    guard3 = InMemoryReplayGuard()
    res_forged = verify_envelope(forged, replay_guard=guard3, strict=True)

    assert not res_forged.valid
    assert res_forged.category == "signature_invalid"

    # ------------------------------------------------------------------
    # 5. Canonicalization determinism
    # ------------------------------------------------------------------
    e1 = create_envelope(
        event_type=EVENT_TYPE,
        payload={"a": 1, "b": 2},
        source=SOURCE,
        key_id=KEY_ID,
    )
    e2 = create_envelope(
        event_type=EVENT_TYPE,
        payload={"b": 2, "a": 1},
        source=SOURCE,
        key_id=KEY_ID,
    )

    assert e1["header"].payload_hash == e2["header"].payload_hash
