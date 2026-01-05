from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from contextlib import AsyncExitStack
from typing import NoReturn
import psycopg2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv
from nekhebet_core import DefaultSigningContext, sign_envelope
from nekhebet_ingest.telegram.adapter import TelegramAdapter
from nekhebet_store.hybrid_repository import HybridEventRepository

# ---------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("nekhebet.ingest.telegram")


# ---------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------
shutdown_event = asyncio.Event()


def _signal_handler(signum: int, frame) -> None:  # type: ignore
    log.info("Received signal %s, shutting down...", signal.strsignal(signum))
    shutdown_event.set()


async def _wait_for_shutdown() -> NoReturn:
    await shutdown_event.wait()
    raise SystemExit(0)


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
async def main() -> None:
    log.info("Starting Nekhebet Telegram ingest (Hybrid PG+LMDB mode)")

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _signal_handler)
    asyncio.create_task(_wait_for_shutdown())

    # ------------------------------------------------------------
    # Database + LMDB (Mechanical Sympathy edition)
    # ------------------------------------------------------------
    conn_params = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "dbname": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "connect_timeout": 10,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5,
    }

    try:
        conn = psycopg2.connect(**conn_params)
        conn.autocommit = False
    except Exception as e:
        log.error("PostgreSQL connection failed: %s", e)
        raise

    lmdb_path = os.getenv("LMDB_PATH", "X:/nekhebet/data/lmdb").rstrip("/\\")
    os.makedirs(lmdb_path, exist_ok=True)

    default_map_size = 1 << 30  # 1 GiB
    lmdb_map_size_str = os.getenv("LMDB_MAP_SIZE")

    if lmdb_map_size_str:
        try:
            lmdb_map_size = int(lmdb_map_size_str)
            if lmdb_map_size < (1 << 27):
                lmdb_map_size = 1 << 27
                log.warning("LMDB_MAP_SIZE too small, forced to 128 MiB")
        except ValueError:
            log.warning("Invalid LMDB_MAP_SIZE value, using default 1 GiB")
            lmdb_map_size = default_map_size
    else:
        lmdb_map_size = default_map_size

    log.info(
        "Initializing Hybrid repository: PostgreSQL + LMDB at %s (map_size=%d GiB)",
        lmdb_path,
        lmdb_map_size >> 30,
    )

    repo = HybridEventRepository(
        pg_conn=conn,
        lmdb_path=lmdb_path,
        map_size=lmdb_map_size,
    )

    log.info("Hybrid repository ready (PostgreSQL + LMDB)")

    # ------------------------------------------------------------
    # Signing context
    # ------------------------------------------------------------
    private_key = Ed25519PrivateKey.generate()  # dev-only!
    public_key = private_key.public_key()
    key_id = os.getenv("NEKHEBET_KEY_ID", "telegram-dev")

    signing_ctx = DefaultSigningContext(
        private_key=private_key,
        public_key=public_key,
        key_id=key_id,
    )

    log.info("Signing context initialized (key_id=%s)", key_id)

    # ------------------------------------------------------------
    # Envelope handler
    # ------------------------------------------------------------
    async def on_envelope(unsigned: dict) -> None:
        try:
            signed = sign_envelope(unsigned, signing_ctx)
            repo.save(signed)
        except Exception as e:
            log.exception("Envelope processing failed: %s", e)

    # ------------------------------------------------------------
    # Telegram adapter
    # ------------------------------------------------------------
    adapter = TelegramAdapter(
        api_id=int(os.getenv("TELEGRAM_API_ID")),
        api_hash=os.getenv("TELEGRAM_API_HASH"),
        session_name=os.getenv("TELEGRAM_SESSION_NAME", "nekhebet_telegram"),
    )

    async with AsyncExitStack() as stack:
        stack.push_async_callback(adapter.client.disconnect)
        stack.callback(conn.close)
        stack.callback(repo.close)

        try:
            await adapter.run_for_chat(
                chat_id=int(os.getenv("TELEGRAM_CHAT_ID", "2527908227")),
                source=os.getenv("TELEGRAM_SOURCE", "telegram"),
                key_id=key_id,
                on_envelope=on_envelope,
            )
        except asyncio.CancelledError:
            log.info("Telegram adapter cancelled")
            raise
        except Exception:
            log.exception("Fatal error in adapter")
            raise
        finally:
            log.info("Shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Stopped gracefully")
        sys.exit(0)
    except Exception:
        log.exception("Crashed")
        sys.exit(1)

