"""
Nekhebet Core v4.0.0 — Replay Guard implementations

Reference in-memory replay protection.

SECURITY NOTES:
- Process-local and non-persistent.
- NOT suitable for distributed or HA systems.
- Use external storage (PostgreSQL / Redis) in production.

SEMANTIC NOTES:
- Replay protection is based on (key_id, nonce, issued_at).
- issued_at is the authoritative event timestamp, NOT wall-clock time.
- Capacity exhaustion is NOT treated as replay.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Tuple, Optional

from .types import ReplayGuardProtocol, MAX_EXPIRES_SECONDS
from .utils import is_iso8601_utc


# Maximum number of stored (key_id, nonce) pairs.
#
# IMPORTANT:
# Actual memory footprint in CPython is significantly higher than raw estimates
# due to dict, tuple and datetime object overhead.
#
# This value MUST be treated as a hard safety cap, not a performance target.
DEFAULT_MAX_STORE_SIZE: int = 10_000_000  # 10 million entries


class InMemoryReplayGuard(ReplayGuardProtocol):
    """
    Thread-safe in-memory replay guard with TTL cleanup.

    This implementation is intended ONLY as:
    - a reference implementation
    - a development / test backend
    - a single-process, best-effort protection layer

    SECURITY BOUNDARY:
    This guard MUST NOT be used in distributed systems.
    """

    def __init__(
        self,
        max_store_size: int = DEFAULT_MAX_STORE_SIZE,
        max_age_seconds: int = MAX_EXPIRES_SECONDS,
        cleanup_interval: int = 1_000,
    ) -> None:
        """
        Args:
            max_store_size: Hard limit on stored (key_id, nonce) pairs
            max_age_seconds: Maximum allowed age based on issued_at
            cleanup_interval: Perform cleanup every N successful insertions
        """
        self.max_store_size = max_store_size
        self.max_age_seconds = max_age_seconds
        self.cleanup_interval = max(1, cleanup_interval)

        # Store maps (key_id, nonce) -> issued_at datetime (UTC)
        self._store: Dict[Tuple[str, str], datetime] = {}

        self._lock = threading.RLock()
        self._insert_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_and_store(self, key_id: str, nonce: str, issued_at: str) -> bool:
        """
        Atomically check and store a (key_id, nonce) pair.

        Returns:
            True  -> new entry stored
            False -> replay detected OR guard rejected the entry

        IMPORTANT:
        - This method MUST be called only AFTER basic timestamp validation
          (issued_at format, expiration, clock skew) has already passed.
        - Capacity exhaustion is treated as a rejection, NOT as replay.
        """
        if not is_iso8601_utc(issued_at):
            # Invalid timestamp format — reject early
            return False

        try:
            issued_dt = datetime.fromisoformat(
                issued_at.replace("Z", "+00:00")
            )
        except ValueError:
            return False

        with self._lock:
            # Opportunistic cleanup (amortized)
            self._insert_count += 1
            if self._insert_count % self.cleanup_interval == 0:
                self._cleanup_expired_locked()

            # Hard capacity limit — reject without misclassifying as replay
            if len(self._store) >= self.max_store_size:
                return False

            key = (key_id, nonce)

            # Replay detected
            if key in self._store:
                return False

            # Store authoritative issued_at timestamp
            self._store[key] = issued_dt
            return True

    def cleanup_expired(self, max_age_seconds: Optional[int] = None) -> None:
        """
        Manually trigger cleanup of expired entries.

        Args:
            max_age_seconds: Override default TTL if provided
        """
        with self._lock:
            self._cleanup_expired_locked(max_age_seconds=max_age_seconds)

    def current_size(self) -> int:
        """
        Return current number of stored entries.

        WARNING:
        This method acquires the internal lock and MUST NOT be used
        in hot paths or performance-critical sections.
        """
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """
        Clear all stored replay entries.

        Intended for:
        - tests
        - controlled lifecycle resets
        """
        with self._lock:
            self._store.clear()
            self._insert_count = 0

    # ------------------------------------------------------------------
    # Internal helpers (lock must be held)
    # ------------------------------------------------------------------

    def _cleanup_expired_locked(
        self,
        max_age_seconds: Optional[int] = None,
    ) -> None:
        """
        Remove entries whose issued_at is older than allowed TTL.

        Lock MUST be held by the caller.
        """
        if not self._store:
            return

        age = (
            max_age_seconds
            if max_age_seconds is not None
            else self.max_age_seconds
        )

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=age)

        # Iterate over a static list to allow safe deletion
        for key, issued_dt in list(self._store.items()):
            if issued_dt < cutoff:
                del self._store[key]
