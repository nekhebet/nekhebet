from __future__ import annotations

import logging
import os
from typing import Iterable, Optional
from uuid import UUID

import lmdb

from nekhebet_core import SignedEnvelope
from nekhebet_core.serialization import to_json_bytes, from_json_bytes

log = logging.getLogger(__name__)


class ReplayDetectedError(Exception):
    """
    Raised when (key_id, nonce) has already been seen.
    Indicates:
    - replay attack
    - duplicate delivery
    - race between ingest workers
    EXPECTED: ingest layer must catch and count as `seth.caught`
    """
    pass


class LMDBEventRepository:
    """
    LMDB-based storage adapter for Nekhebet signed envelopes.
    Contract: Core ↔ Store v4.0 (opaque envelope)

    Guarantees:
    - Idempotency via content_hash (NOOVERWRITE)
    - Replay protection via (key_id, nonce)
    - Atomicity (single LMDB transaction)
    - Zero-copy reads (mmap)
    - Single-writer, multi-reader safety

    Databases:
    - events: content_hash -> envelope bytes
    - replay_guard: key_id:nonce -> issued_at (ISO string)
    """

    DB_EVENTS = b"events"
    DB_REPLAY = b"replay_guard"

    __slots__ = ("env", "_events", "_replay")

    def __init__(
        self,
        path: str,
        *,
        map_size: int = 1 << 30,  # 1 GiB default — safe for Windows and dev
        readonly: bool = False,
    ) -> None:
        os.makedirs(path, exist_ok=True)

        self.env = lmdb.Environment(
            path,
            map_size=map_size,
            max_dbs=2,
            readonly=readonly,
            lock=not readonly,
            sync=True,        # durability
            metasync=True,
            writemap=False,   # better for Windows
            map_async=False,
        )

        with self.env.begin(write=not readonly) as txn:
            self._events = self.env.open_db(self.DB_EVENTS, txn=txn)
            self._replay = self.env.open_db(self.DB_REPLAY, txn=txn)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _replay_key(key_id: str, nonce: str) -> bytes:
        """Cache-friendly deterministic key."""
        return f"{key_id}:{nonce}".encode("utf-8")

    @staticmethod
    def _normalize_issued_at(issued_at: str) -> str:
        """
        In Nekhebet Core, issued_at is always an ISO string ending with 'Z'.
        Assume it's already normalized.
        """
        # In Nekhebet v4.0, issued_at is always a proper ISO string
        return issued_at

    # ------------------------------------------------------------------ save
    def save(self, envelope: SignedEnvelope) -> None:
        """
        Persist envelope with replay protection and idempotency guarantees.
        """
        header = envelope.header
        blob = to_json_bytes(envelope)
        content_key = header.payload_hash.encode("utf-8")
        replay_key = self._replay_key(header.key_id, header.nonce)

        with self.env.begin(write=True) as txn:
            # Replay guard check and insert
            existing = txn.get(replay_key, db=self._replay)
            if existing is not None:
                log.warning(
                    "Replay detected (LMDB): key_id=%s nonce=%s issued_at=%s",
                    header.key_id[:16],
                    header.nonce[:16],
                    header.issued_at,
                )
                raise ReplayDetectedError("Nonce already used for this key_id")

            # Store replay entry
            txn.put(
                replay_key,
                header.issued_at.encode("utf-8"),
                db=self._replay,
                overwrite=False,
            )

            # Main event blob
            inserted = txn.put(
                content_key,
                blob,
                db=self._events,
                overwrite=False,
            )
            if not inserted:
                log.info(
                    "Duplicate payload ignored (LMDB): content_hash=%s",
                    header.payload_hash[:16],
                )
                # Idempotent success — no further action needed

    # ------------------------------------------------------------------ get by content_hash (recommended fast path)
    def get_by_hash(self, content_hash: str) -> Optional[SignedEnvelope]:
        """O(1) fetch by payload_hash — primary production path."""
        key = content_hash.encode("utf-8")
        with self.env.begin() as txn:
            blob = txn.get(key, db=self._events)
            if blob is None:
                return None
            return from_json_bytes(blob)

    # ------------------------------------------------------------------ get by id (fallback, O(n) — dev/debug only)
    def get(self, event_id: str | UUID) -> Optional[SignedEnvelope]:
        """
        Fetch by event id — O(n) scan.
        In production, use get_by_hash or an external index.
        """
        log.debug("LMDB.get(event_id=%s) — O(n) scan (dev only)", event_id)
        with self.env.begin() as txn:
            with txn.cursor(db=self._events) as cur:
                for _, value in cur:
                    envelope = from_json_bytes(value)
                    if str(envelope.header.id) == str(event_id):
                        return envelope
        return None

    # ------------------------------------------------------------------ iter_all
    def iter_all(self, *, limit: Optional[int] = None) -> Iterable[SignedEnvelope]:
        """Zero-copy iteration over all envelopes."""
        count = 0
        with self.env.begin() as txn:
            with txn.cursor(db=self._events) as cur:
                for _, value in cur:
                    yield from_json_bytes(value)
                    count += 1
                    if limit is not None and count >= limit:
                        return

    # ------------------------------------------------------------------ cleanup
    def cleanup_replay_guard(self, *, older_than_iso: str) -> int:
        """Safe removal of old replay entries."""
        deleted = 0
        with self.env.begin(write=True) as txn:
            with txn.cursor(db=self._replay) as cur:
                for key, value in cur:
                    if value.decode("utf-8") < older_than_iso:
                        cur.delete()
                        deleted += 1
        log.info("Replay guard cleanup (LMDB): %d entries removed", deleted)
        return deleted
