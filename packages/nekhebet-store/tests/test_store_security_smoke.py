#!/usr/bin/env python3
"""
Nekhebet Store — Security Contract Test

This test validates the full security contract of nekhebet-store:
- atomic persistence with replay protection
- idempotency by payload hash
- replay rejection
- retrieval integrity
- hybrid repository consistency

Covers:
- EventRepository (PostgreSQL)
- LMDBEventRepository
- HybridEventRepository

This is NOT a regular test suite.
This is a cryptographic security contract smoke test.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Optional: load .env for DB credentials (safe if python-dotenv not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not available — use defaults

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT, connection as PsycopgConnection

from nekhebet_core import (
    create_envelope,
    sign_envelope,
    verify_envelope,
    DefaultSigningContext,
    SignedEnvelope,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nekhebet_store.pg_repository import EventRepository, ReplayDetectedError as PGReplayError
from nekhebet_store.lmdb_repository import LMDBEventRepository, ReplayDetectedError as LMDBReplayError
from nekhebet_store.hybrid_repository import HybridEventRepository


EVENT_TYPE = "omen.observed"
SOURCE = "store-security-test"
KEY_ID = "store-test-key"


def get_pg_connection(dbname: str) -> PsycopgConnection:
    """Universal connection function with .env support or defaults."""
    return psycopg2.connect(
        dbname=dbname,
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),  # Empty if no password
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
    )


def test_store_security_contract() -> None:
    # ------------------------------------------------------------------
    # Setup signing context
    # ------------------------------------------------------------------
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    ctx = DefaultSigningContext(private_key=priv, public_key=pub, key_id=KEY_ID)

    payload = {"msg": "store contract", "value": 2026}

    # Reliable path to schema.sql

    schema_path = Path(__file__).resolve().parent.parent / "nekhebet_store" / "schema.sql"

    if not schema_path.exists():
        raise FileNotFoundError(f"schema.sql not found at {schema_path}")

    # ------------------------------------------------------------------
    # 1. PostgreSQL repository
    # ------------------------------------------------------------------
    conn = get_pg_connection("postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    with conn.cursor() as cur:
        cur.execute("DROP DATABASE IF EXISTS nekhebet_test_pg;")
        cur.execute("CREATE DATABASE nekhebet_test_pg;")
    conn.close()

    conn = get_pg_connection("nekhebet_test_pg")
    with open(schema_path) as f, conn.cursor() as cur:
        cur.execute(f.read())
    conn.commit()

    repo_pg = EventRepository(conn)

    env1 = create_envelope(event_type=EVENT_TYPE, payload=payload, source=SOURCE, key_id=KEY_ID)
    signed1: SignedEnvelope = sign_envelope(env1, ctx)
    assert verify_envelope(signed1, strict=True).valid

    repo_pg.save(signed1)

    # Replay → must raise
    try:
        repo_pg.save(signed1)
    except PGReplayError:
        pass
    else:
        raise AssertionError("PostgreSQL replay must be rejected")

    # Same payload, new nonce → accepted
    env2 = create_envelope(event_type=EVENT_TYPE, payload=payload, source=SOURCE, key_id=KEY_ID)
    signed2: SignedEnvelope = sign_envelope(env2, ctx)
    repo_pg.save(signed2)

    fetched = repo_pg.get(signed1.header.id)
    assert fetched is not None and verify_envelope(fetched, strict=True).valid

    conn.close()

    # ------------------------------------------------------------------
    # 2. LMDB repository
    # ------------------------------------------------------------------
    lmdb_path = tempfile.mkdtemp(prefix="lmdb_test_")
    repo_lmdb = LMDBEventRepository(lmdb_path)

    env3 = create_envelope(event_type=EVENT_TYPE, payload=payload, source=SOURCE, key_id=KEY_ID)
    signed3: SignedEnvelope = sign_envelope(env3, ctx)
    repo_lmdb.save(signed3)

    try:
        repo_lmdb.save(signed3)
    except LMDBReplayError:
        pass
    else:
        raise AssertionError("LMDB replay must be rejected")

    env4 = create_envelope(event_type=EVENT_TYPE, payload=payload, source=SOURCE, key_id=KEY_ID)
    signed4: SignedEnvelope = sign_envelope(env4, ctx)
    repo_lmdb.save(signed4)

    fetched_lmdb = repo_lmdb.get_by_hash(signed3.header.payload_hash)
    assert fetched_lmdb is not None and verify_envelope(fetched_lmdb, strict=True).valid

    shutil.rmtree(lmdb_path)

    # ------------------------------------------------------------------
    # 3. Hybrid repository
    # ------------------------------------------------------------------
    hybrid_db = "nekhebet_test_hybrid"
    conn = get_pg_connection("postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    with conn.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS {hybrid_db};")
        cur.execute(f"CREATE DATABASE {hybrid_db};")
    conn.close()

    conn = get_pg_connection(hybrid_db)
    with open(schema_path) as f, conn.cursor() as cur:
        cur.execute(f.read())
    conn.commit()

    hybrid_lmdb = tempfile.mkdtemp(prefix="hybrid_lmdb_")
    hybrid_pg_conn = get_pg_connection(hybrid_db)
    repo_hybrid = HybridEventRepository(hybrid_pg_conn, hybrid_lmdb)

    env5 = create_envelope(event_type=EVENT_TYPE, payload=payload, source=SOURCE, key_id=KEY_ID)
    signed5: SignedEnvelope = sign_envelope(env5, ctx)
    repo_hybrid.save(signed5)

    try:
        repo_hybrid.save(signed5)
    except Exception:  # Replay from PG or LMDB
        pass
    else:
        raise AssertionError("Hybrid replay must be rejected")

    env6 = create_envelope(event_type=EVENT_TYPE, payload=payload, source=SOURCE, key_id=KEY_ID)
    signed6: SignedEnvelope = sign_envelope(env6, ctx)
    repo_hybrid.save(signed6)

    fetched_hybrid = repo_hybrid.get(signed5.header.id)
    assert fetched_hybrid is not None and verify_envelope(fetched_hybrid, strict=True).valid

    repo_hybrid.close()
    shutil.rmtree(hybrid_lmdb)

    # ------------------------------------------------------------------
    # Final cleanup: drop test databases
    # ------------------------------------------------------------------
    conn = get_pg_connection("postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    with conn.cursor() as cur:
        cur.execute("DROP DATABASE IF EXISTS nekhebet_test_pg;")
        cur.execute(f"DROP DATABASE IF EXISTS {hybrid_db};")
    conn.close()

    print("OK. STORE SECURITY CONTRACT SATISFIED.")


if __name__ == "__main__":
    try:
        test_store_security_contract()
        sys.exit(0)
    except AssertionError as e:
        print(f"ERROR STORE SECURITY CONTRACT VIOLATION: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR IN STORE CONTRACT TEST: {e}")
        sys.exit(1)
