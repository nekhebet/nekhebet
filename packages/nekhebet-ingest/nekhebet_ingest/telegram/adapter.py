from __future__ import annotations
from nekhebet_core import create_envelope
from nekhebet_ingest.telegram.mapper import telegram_message_to_payload
from telethon import TelegramClient, events


class TelegramAdapter:
    """
    Telegram → Nekhebet UnsignedEnvelope adapter.

    IMPORTANT:
    - Stateless
    - No storage knowledge
    - No replay / security logic
    """

    def __init__(
        self,
        *,
        api_id: int,
        api_hash: str,
        session_name: str = "nekhebet",
    ) -> None:
        self.client = TelegramClient(
            session_name,
            api_id=api_id,
            api_hash=api_hash,
        )

    async def run_for_chat(
        self,
        *,
        chat_id: int,
        source: str,
        key_id: str,
        on_envelope,
    ) -> None:
        """Listen to Telegram chat and emit unsigned envelopes."""

        await self.client.start()

        @self.client.on(events.NewMessage(chats=chat_id))
        async def handler(event: events.NewMessage.Event):
            msg = event.message

            payload = telegram_message_to_payload(
                msg,
                chat_id=chat_id,
            )

            envelope = create_envelope(
                event_type="omen.observed",
                payload=payload,
                source=source,
                key_id=key_id,
            )

            await on_envelope(envelope)

        await self.client.run_until_disconnected()
