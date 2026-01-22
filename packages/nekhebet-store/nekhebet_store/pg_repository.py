from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterable, Optional, Generator, TypedDict, cast
from uuid import UUID

from psycopg2.extensions import connection as PsycopgConnection
from psycopg2.extras import RealDictCursor

from nekhebet_core import SignedEnvelope
from nekhebet_core.serialization import to_json_bytes, from_json_bytes

log = logging.getLogger(__name__)


class ReplayDetectedError(Exception):
    """
    Raised when a (key_id, nonce) pair has already been seen.

    Indicates:
    - replay attack
    - OR legitimate duplicate caused by retry / race

    EXPECTED:
    Ingest layer must treat it as handled
    and increment metric: seth.caught
    """
    pass


class EventMetadata(TypedDict, total=False):
    """Type definition for event metadata."""
    id: str
    event_type: str
    issued_at: str
    source: str
    content_hash: str


class EventRepository:
    """
    PostgreSQL-backed storage adapter for Nekhebet envelopes.

    Contract: Core ↔ Store v4.0 (opaque envelope)

    Responsibilities:
    - Replay protection via (key_id, nonce)
    - Idempotency via content_hash
    - Atomic persistence
    """

    def __init__(self, connection: PsycopgConnection) -> None:
        self._conn = connection

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _cursor(self) -> Generator[RealDictCursor, None, None]:
        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            yield cur

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self, envelope: SignedEnvelope) -> None:
        """
        Persist a signed envelope with replay protection.

        Atomic transaction:
        1. INSERT replay_guard
        2. INSERT events
        3. COMMIT
        """
        header = envelope.header

        try:
            with self._cursor() as cur:
                # Replay guard
                cur.execute(
                    """
                    INSERT INTO replay_guard (key_id, nonce, issued_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (key_id, nonce) DO NOTHING
                    """,
                    (
                        header.key_id,
                        header.nonce,
                        header.issued_at,
                    ),
                )

                if cur.rowcount == 0:
                    log.warning(
                        "Replay detected: key_id=%s nonce=%s issued_at=%s",
                        header.key_id[:16],
                        header.nonce[:16],
                        header.issued_at,
                    )
                    raise ReplayDetectedError(
                        "Nonce already used for this key_id"
                    )

                # Main event
                cur.execute(
                    """
                    INSERT INTO events (
                        id,
                        event_type,
                        issued_at,
                        source,
                        content_hash,
                        envelope
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (content_hash) DO NOTHING
                    """,
                    (
                        str(header.id),
                        header.type,
                        header.issued_at,
                        header.source,
                        header.payload_hash,
                        to_json_bytes(envelope),
                    ),
                )

                if cur.rowcount == 0:
                    log.info(
                        "Duplicate payload ignored (different nonce): "
                        "event_id=%s type=%s",
                        str(header.id)[:8],
                        header.type,
                    )

            self._conn.commit()

        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Metadata-only access (authoritative index)
    # ------------------------------------------------------------------

    def get_metadata(self, event_id: str | UUID) -> Optional[EventMetadata]:
        """
        Fetch event metadata WITHOUT envelope blob.

        Used by HybridEventRepository as authoritative index:
        event_id → content_hash
        """
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    event_type,
                    issued_at,
                    source,
                    content_hash
                FROM events
                WHERE id = %s
                """,
                (str(event_id),),
            )
            row = cur.fetchone()
            
        if row is None:
            return None
            
        # Convert RealDictRow to EventMetadata
        return cast(EventMetadata, {
            "id": row["id"],
            "event_type": row["event_type"],
            "issued_at": row["issued_at"],
            "source": row["source"],
            "content_hash": row["content_hash"],
        })

    # ------------------------------------------------------------------
    # Get full envelope
    # ------------------------------------------------------------------

    def get(self, event_id: str | UUID) -> Optional[SignedEnvelope]:
        """
        Fetch full envelope by event id.

        Notes:
        - O(1) via primary key
        - No verification here
        """
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT envelope
                FROM events
                WHERE id = %s
                """,
                (str(event_id),),
            )
            row = cur.fetchone()

        if row is None:
            return None

        return from_json_bytes(row["envelope"])

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    def iter_by_type(
        self,
        event_type: str,
        *,
        limit: Optional[int] = None,
    ) -> Iterable[SignedEnvelope]:
        """
        Iterate envelopes by event type.
        """
        query = """
            SELECT envelope
            FROM events
            WHERE event_type = %s
            ORDER BY issued_at ASC
        """
        params: list[object] = [event_type]

        if limit is not None:
            query += " LIMIT %s"
            params.append(limit)

        with self._cursor() as cur:
            cur.execute(query, params)
            for row in cur.fetchall():
                yield from_json_bytes(row["envelope"])
