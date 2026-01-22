"""
Nekhebet Core v4.0.0 — Event type registry

Defines allowed event types and their security policies.
"""

from __future__ import annotations

from typing import Dict, Final, Mapping, Any
from types import MappingProxyType

# =============================================================================
# Event Type Registry
# =============================================================================

# Immutable registry of event types.
#
# Each event type defines:
# - require_secure_nonce: whether a cryptographically strong nonce is required
# - max_payload_multiplier: payload size multiplier relative to base limit
# - description: documentation and audit context

_EVENT_REGISTRY: Final[Dict[str, Dict[str, Any]]] = {
    "omen.observed": {
        "description": "Raw observation from collector",
        "require_secure_nonce": True,
        "max_payload_multiplier": 1.0,
    },
    "observation.recorded": {
        "description": "Normalized observation recorded",
        "require_secure_nonce": True,
        "max_payload_multiplier": 1.0,
    },
    "anubis.weighed": {
        "description": "Observation analyzed and validated",
        "require_secure_nonce": True,
        "max_payload_multiplier": 1.0,
    },
    "charon.transported": {
        "description": "Event routed or delivered to external system",
        "require_secure_nonce": False,
        "max_payload_multiplier": 2.0,
    },
    "osiris.remembered": {
        "description": "Event persisted as immutable record",
        "require_secure_nonce": True,
        "max_payload_multiplier": 1.0,
    },
    "seth.caught": {
        "description": "Anomaly or replay attack detected",
        "require_secure_nonce": True,
        "max_payload_multiplier": 0.5,
    },
}

# Export registry as read-only mapping
EVENT_REGISTRY: Mapping[str, Mapping[str, Any]] = MappingProxyType(_EVENT_REGISTRY)


def get_event_policy(event_type: str) -> Mapping[str, Any]:
    """
    Get security policy for a given event type.

    Args:
        event_type: Event type identifier

    Returns:
        Mapping: Security policy for the event type

    Raises:
        ValueError: If event_type is not registered.
    """
    if event_type not in EVENT_REGISTRY:
        raise ValueError(
            f"Unknown event type: {event_type}. "
            f"Must be one of {sorted(EVENT_REGISTRY.keys())}"
        )

    return EVENT_REGISTRY[event_type]
