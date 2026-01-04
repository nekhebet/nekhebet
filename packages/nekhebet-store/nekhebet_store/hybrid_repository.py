from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from psycopg2.extensions import connection as PsycopgConnection

from nekhebet_core import SignedEnvelope
from nekhebet_store.pg_repository import EventRepository as PGEventRepository
from nekhebet_store.pg_repository import ReplayDetectedError as PGReplayError
from nekhebet_store.lmdb_repository import LMDBEventRepository
from nekhebet_store.lmdb_repository import ReplayDetectedError as LMDBReplayError

log = logging.getLogger(__name__)


class HybridEventRepository:
    """
    Hybrid storage for Nekhebet v4.0 (PostgreSQL + LMDB).

    PostgreSQL — authoritative source for metadata, replay protection, and analytics.
    LMDB — ultra-fast mmap storage for full SignedEnvelope blobs.

    Logical atomicity: PG first (critical), then LMDB.
    """

    __slots__ = ("pg", "lmdb")

    def __init__(
        self,
        pg_conn: PsycopgConnection,   # psycopg2 connection
        lmdb_path: str,
        *,
        map_size: int = 1 << 40,      # 1 TB virtual space
    ) -> None:
        self.pg = PGEventRepository(pg_conn)
        self.lmdb = LMDBEventRepository(path=lmdb_path, map_size=map_size)

        log.info(
            "HybridEventRepository initialized: PostgreSQL + LMDB (%s, map_size=%d GB)",
            lmdb_path,
            map_size >> 30,
        )

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self, envelope: SignedEnvelope) -> None:
        """
        Logically atomic write to hybrid storage.

        1. Replay protection + metadata → PostgreSQL (authoritative)
        2. Full blob → LMDB (only after PG success)

        If PG fails, nothing is written to LMDB.
        """
        header = envelope.header

        try:
            self.pg.save(envelope)
            log.debug("Hybrid save: metadata OK (id=%s)", str(header.id)[:8])
        except PGReplayError:
            raise
        except Exception as e:
            log.error(
                "Hybrid save FAILED: PostgreSQL error (id=%s): %s",
                str(header.id)[:8],
                e,
            )
            raise

        try:
            self.lmdb.save(envelope)
            log.debug("Hybrid save: LMDB blob OK (id=%s)", str(header.id)[:8])
        except LMDBReplayError:
            # Theoretically impossible: PG already checked replay
            log.critical(
                "Hybrid inconsistency: LMDB replay after PG success (id=%s)",
                str(header.id)[:8],
            )
            raise
        except Exception as e:
            # CRITICAL: metadata in PG exists, blob missing
            log.critical(
                "HYBRID INCONSISTENCY: PG saved but LMDB failed (id=%s): %s",
                str(header.id)[:8],
                e,
            )
            raise

    # ------------------------------------------------------------------
    # Get (read-only, production-safe)
    # ------------------------------------------------------------------

    def get(self, event_id: str | UUID) -> Optional[SignedEnvelope]:
        """
        Fetch full SignedEnvelope by event id.

        Contract:
        - PostgreSQL = authoritative index (event_id → content_hash)
        - LMDB = blob store (content_hash → envelope)

        IMPORTANT:
        - This method is READ-ONLY.
        - No repair, no writes, no O(n) scans.
        """
        # 1. Authoritative metadata lookup
        meta = self.pg.get_metadata(event_id)
        if meta is None:
            return None

        content_hash = meta["content_hash"]

        # 2. Fast blob fetch
        envelope = self.lmdb.get_by_hash(content_hash)
        if envelope is not None:
            return envelope

        # 3. Inconsistency detected: fallback to PG (availability > speed)
        log.error(
            "Hybrid inconsistency detected: missing LMDB blob "
            "(id=%s, content_hash=%s)",
            str(event_id),
            content_hash[:16],
        )
        return self.pg.get(event_id)

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Explicit resource cleanup (optional on shutdown)."""
        try:
            self.pg._conn.close()
        except Exception as e:
            log.warning("Hybrid close: PG connection close error: %s", e)
        # LMDB closes automatically on process termination
