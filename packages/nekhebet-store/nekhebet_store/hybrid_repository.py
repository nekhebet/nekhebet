from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from nekhebet_core import SignedEnvelope
from nekhebet_store.pg_repository import EventRepository as PGEventRepository
from nekhebet_store.pg_repository import ReplayDetectedError as PGReplayError
from nekhebet_store.lmdb_repository import LMDBEventRepository
from nekhebet_store.lmdb_repository import ReplayDetectedError as LMDBReplayError

log = logging.getLogger(__name__)


class HybridEventRepository:
    """
    Гибридное хранилище Nekhebet v4.0 (PostgreSQL + LMDB).

    PostgreSQL — авторитетный источник метаданных, replay-защиты и аналитики.
    LMDB — сверхбыстрое mmap-хранилище полного SignedEnvelope (blob).

    Логическая атомарность: сначала PG (критично), потом LMDB.
    """

    __slots__ = ("pg", "lmdb")  # Mechanical Sympathy: избегаем __dict__

    def __init__(
        self,
        pg_conn,                     # psycopg2 connection
        lmdb_path: str,
        *,
        map_size: int = 1 << 40,      # 1 TB виртуального пространства
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
        Атомарная (логически) запись в гибрид.

        1. Replay-защита + метаданные → PostgreSQL (authoritative)
        2. Полный blob → LMDB (только после успеха PG)

        Если PG провалится — ничего не пишется в LMDB.
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
            # Теоретически невозможно: PG уже проверил replay
            log.critical(
                "Hybrid inconsistency: LMDB replay after PG success (id=%s)",
                str(header.id)[:8],
            )
            raise
        except Exception as e:
            # КРИТИЧНО: метаданные в PG есть, blob отсутствует
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
            self.pg._conn.close()  # type: ignore[attr-defined]
        except Exception as e:
            log.warning("Hybrid close: PG connection close error: %s", e)
        # LMDB закрывается автоматически при завершении процесса
