"""
Nekhebet Core v4.0.0 — Metrics collection
Thread-safe metrics for signing, verification and security events.
Designed for integration with Prometheus, StatsD or simple logging.
"""

from __future__ import annotations

import time
import threading
from collections import Counter, deque
from typing import Deque, Dict, Any, Optional

# =============================================================================
# Singleton Metrics Collector
# =============================================================================

class EventMetrics:
    """
    Global metrics collector for Nekhebet operations.
    
    Thread-safe, low-overhead, keeps recent samples for averages.
    """
    
    _instance: "EventMetrics | None" = None
    _lock = threading.RLock()
    _initialized: bool
    
    def __new__(cls) -> "EventMetrics":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        if self._initialized:
            return
        with self._lock:
            self._init_metrics()
            self._initialized = True
    
    def _init_metrics(self) -> None:
        # Counters
        self.signing_total: Counter[str] = Counter()
        self.verification_total: Counter[str] = Counter()
        self.verification_errors: Counter[str] = Counter()  # by category
        self.replay_detected: int = 0
        self.unsigned_rejected: int = 0  # legacy, if ever needed
        
        # Timing samples (fixed-size deques for recent values)
        self.signing_times_ms: Deque[float] = deque(maxlen=1000)
        self.verification_times_ms: Deque[float] = deque(maxlen=1000)
    
    # =============================================================================
    # Recording methods
    # =============================================================================
    
    def record_signing(self, event_type: str, duration_ms: float) -> None:
        with self._lock:
            self.signing_total[event_type] += 1
            self.signing_times_ms.append(duration_ms)
    
    def record_verification(
        self,
        event_type: str,
        duration_ms: float,
        valid: bool,
        category: Optional[str] = None,
    ) -> None:
        with self._lock:
            outcome = "success" if valid else "failure"
            key = f"{event_type}:{outcome}"
            self.verification_total[key] += 1
            self.verification_times_ms.append(duration_ms)
            if not valid and category:
                self.verification_errors[category] += 1
    
    def record_replay_detected(self) -> None:
        with self._lock:
            self.replay_detected += 1
    
    # =============================================================================
    # Retrieval
    # =============================================================================
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Return current metrics snapshot (thread-safe copy).
        Suitable for Prometheus exposition or logging.
        
        Returns:
            Dict: Current metrics snapshot
        """
        with self._lock:
            signing_samples = len(self.signing_times_ms)
            verification_samples = len(self.verification_times_ms)
            
            avg_signing = (
                sum(self.signing_times_ms) / signing_samples
                if signing_samples > 0 else 0.0
            )
            avg_verification = (
                sum(self.verification_times_ms) / verification_samples
                if verification_samples > 0 else 0.0
            )
            
            return {
                "signing": {
                    "total_by_type": dict(self.signing_total),
                    "avg_time_ms": round(avg_signing, 3),
                    "samples": signing_samples,
                },
                "verification": {
                    "total_by_outcome": dict(self.verification_total),
                    "error_by_category": dict(self.verification_errors),
                    "avg_time_ms": round(avg_verification, 3),
                    "samples": verification_samples,
                },
                "security": {
                    "replay_detected": self.replay_detected,
                },
                "timestamp": time.time(),
            }
    
    def reset(self) -> None:
        """Reset all metrics — useful in tests."""
        with self._lock:
            self._init_metrics()


# Global instance
metrics = EventMetrics()


# =============================================================================
# Convenience functions (exported for easy use)
# =============================================================================

def record_signing(event_type: str, start_time: float) -> None:
    """
    Convenience function to record signing metrics.

    Args:
        event_type: Type of event being signed
        start_time: Time when signing started (from time.time())
    """
    duration_ms = (time.time() - start_time) * 1000
    metrics.record_signing(event_type, duration_ms)


def record_verification(
    event_type: str,
    start_time: float,
    result: dict[str, Any],
) -> None:
    """
    Convenience function to record verification metrics.

    Args:
        event_type: Type of event being verified
        start_time: Time when verification started (from time.time())
        result: Verification result dictionary containing at least:
                - "valid": bool
                - optionally "category": str or VerificationCategory
    """
    duration_ms = (time.time() - start_time) * 1000
    metrics.record_verification(
        event_type=event_type,
        duration_ms=duration_ms,
        valid=result["valid"],
        category=result.get("category"),
    )

# Export for easy access
__all__ = ["metrics", "record_signing", "record_verification", "EventMetrics"]
