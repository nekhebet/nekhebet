from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, List

from telethon.tl.types import Message


def telegram_message_to_payload(
    message: Message,
    *,
    chat_id: int,
) -> Dict[str, Any]:
    """
    Map Telegram Message → Nekhebet payload (v4.0).

    Invariants:
    - JSON-serializable
    - Deterministic
    - Stable across retries / replays
    """

    sender = message.sender

    payload: Dict[str, Any] = {
        "platform": "telegram",

        # ---- routing / sharding keys
        "chat_id": chat_id,
        "message_id": message.id,

        # ---- time
        "date": (
            message.date.astimezone(timezone.utc).isoformat()
            if message.date
            else None
        ),

        # ---- content
        "text": message.text or "",

        # ---- author (user-centric)
        "author": {
            "id": str(sender.id) if sender else None,
            "username": getattr(sender, "username", None),
            "first_name": getattr(sender, "first_name", None),
            "last_name": getattr(sender, "last_name", None),
        },

        # ---- engagement (non-authoritative, may change)
        "metrics": {
            "views": message.views,
            "forwards": message.forwards,
            "replies": (
                message.replies.replies
                if message.replies
                else None
            ),
        },

        # ---- flags
        "flags": {
            "is_reply": bool(message.is_reply),
            "is_forward": message.fwd_from is not None,
            "has_media": message.media is not None,
        },

        # ---- media metadata only
        "media": _extract_media(message),
    }

    return payload


# ---------------------------------------------------------------------

def _extract_media(message: Message) -> List[Dict[str, Any]]:
    """
    Extract media metadata only.

    IMPORTANT:
    - No file download here
    - Media pipeline is handled by Charon Vessel
    """
    media: List[Dict[str, Any]] = []

    if message.photo:
        media.append({
            "type": "photo",
            "id": message.photo.id,
        })

    if message.document:
        doc = message.document
        media.append({
            "type": "document",
            "id": doc.id,
            "mime_type": doc.mime_type,
            "size": doc.size,
        })

    return media

