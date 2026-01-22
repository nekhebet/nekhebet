"""
Nekhebet Core v4.0.0 — Runtime configuration

Typed, cached configuration loaded from environment variables.

SECURITY NOTES:
- Configuration is treated as a security boundary.
- Any change in defaults or semantics MUST be considered a breaking change.
- Values are cached with TTL to avoid repeated env access.
"""

from __future__ import annotations

import os
import time
import threading
from typing import Final

import msgspec


# =============================================================================
# Defaults (SECURITY INVARIANTS)
# =============================================================================

# Absolute hard limit — canonicalized payload must never exceed this value.
# This invariant is enforced both here and during runtime.
MAX_ABSOLUTE_PAYLOAD_SIZE: Final[int] = 1024 * 1024  # 1 MiB (matches types.py)

# Reasonable defaults that allow event policies to effectively use multipliers
# (both <1.0 for restrictive types and >1.0 for trusted large events).
DEFAULT_BASE_PAYLOAD_SIZE: Final[int] = 256 * 1024   # 256 KiB — flexible starting point
MIN_REASONABLE_PAYLOAD_SIZE: Final[int] = 64 * 1024  # 64 KiB — prevent absurdly low values

DEFAULT_REQUIRE_SECURE_NONCE: Final[bool] = True

DEFAULT_CONFIG_TTL: Final[int] = 60        # seconds
MIN_CONFIG_TTL: Final[int] = 5             # seconds


# =============================================================================
# Typed configuration object
# =============================================================================

class Config(msgspec.Struct, frozen=True, kw_only=True):
    """
    Immutable runtime configuration for Nekhebet Core.

    All fields are security-relevant and must remain stable
    across minor releases.
    """

    base_payload_size: int
    require_secure_nonce_global: bool


# =============================================================================
# Internal cache with TTL
# =============================================================================

class _ConfigCache:
    """Thread-safe configuration cache with configurable TTL."""

    def __init__(self, ttl: int) -> None:
        self.ttl: int = ttl
        self._config: Config | None = None
        self._last_load: float = 0.0
        self._lock = threading.RLock()

    def get(self) -> Config:
        with self._lock:
            now = time.time()
            if self._config is None or now - self._last_load > self.ttl:
                self._config = self._load_config()
                self._last_load = now
            return self._config

    def clear(self) -> None:
        with self._lock:
            self._config = None
            self._last_load = 0.0

    def _load_config(self) -> Config:
        """Load and validate configuration from environment variables."""

        base_payload_str = os.getenv(
            "NEKHEBET_MAX_PAYLOAD_SIZE",
            str(DEFAULT_BASE_PAYLOAD_SIZE),
        )
        try:
            base_payload_size = int(base_payload_str)
        except ValueError:
            base_payload_size = DEFAULT_BASE_PAYLOAD_SIZE

        # Enforce reasonable bounds
        if base_payload_size > MAX_ABSOLUTE_PAYLOAD_SIZE:
            base_payload_size = MAX_ABSOLUTE_PAYLOAD_SIZE
        elif base_payload_size < MIN_REASONABLE_PAYLOAD_SIZE:
            base_payload_size = DEFAULT_BASE_PAYLOAD_SIZE

        require_secure_str = os.getenv(
            "NEKHEBET_REQUIRE_SECURE_NONCE",
            "true" if DEFAULT_REQUIRE_SECURE_NONCE else "false",
        ).strip().lower()

        require_secure_nonce_global = require_secure_str in {
            "1", "true", "yes", "on"
        }

        return Config(
            base_payload_size=base_payload_size,
            require_secure_nonce_global=require_secure_nonce_global,
        )


# =============================================================================
# Cache initialization
# =============================================================================

_ttl_str = os.getenv("NEKHEBET_CONFIG_TTL", str(DEFAULT_CONFIG_TTL))
try:
    _ttl = max(int(_ttl_str), MIN_CONFIG_TTL)
except ValueError:
    _ttl = DEFAULT_CONFIG_TTL

_config_cache = _ConfigCache(ttl=_ttl)


# =============================================================================
# Public API
# =============================================================================

def get_config() -> Config:
    """Return the current immutable runtime configuration."""
    return _config_cache.get()


def clear_config_cache() -> None:
    """Force reload of configuration on the next get_config() call."""
    _config_cache.clear()