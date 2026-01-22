-- ============================================================================
-- Nekhebet Core Storage Schema v4.0
-- Event-first, append-only, envelope-based
--
-- CONTRACT:
-- - Store is cryptography-agnostic
-- - Signature, public key, key_id live ONLY inside opaque envelope
-- - Store operates on metadata + opaque BYTEA envelope
-- - Replay protection is STATEFUL and happens at storage boundary
--
-- DESIGN PRINCIPLES:
-- - Append-only
-- - Deterministic idempotency
-- - Minimal trusted state
-- - Ready for hybrid storage (PostgreSQL + LMDB + filesystem)
-- ============================================================================


-- ============================================================================
-- EVENTS
-- ============================================================================
-- Core immutable event log.
-- Each row represents ONE cryptographically signed fact.
-- ============================================================================

CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY,          -- header.id
    event_type      TEXT NOT NULL,              -- header.type
    issued_at       TIMESTAMPTZ NOT NULL,       -- header.issued_at
    source          TEXT NOT NULL,              -- header.source

    content_hash    TEXT NOT NULL,              -- header.payload_hash (SHA-256 hex)
    envelope        BYTEA NOT NULL,             -- opaque signed envelope

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Idempotency:
-- Exact payload duplicates are rejected deterministically.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_content_hash
    ON events (content_hash);

-- ---------------------------------------------------------------------------
-- Query support (metadata only — payload is opaque by contract)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_events_type_issued
    ON events (event_type, issued_at);

CREATE INDEX IF NOT EXISTS idx_events_source_issued
    ON events (source, issued_at);


-- ============================================================================
-- REPLAY GUARD
-- ============================================================================
-- Purpose:
-- - Prevent replay attacks
-- - Allow honest retries (new nonce)
-- - Enforce cryptographic uniqueness boundary
--
-- Replay key = (key_id, nonce)
-- Both values are signed inside the envelope header.
--
-- IMPORTANT:
-- - This table is SECURITY-CRITICAL
-- - It is the ONLY mutable security state in the system
-- - No UPDATEs, only INSERT + DELETE (cleanup)
-- ============================================================================

CREATE TABLE IF NOT EXISTS replay_guard (
    key_id    TEXT        NOT NULL,
    nonce     TEXT        NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (key_id, nonce)
);

-- For cleanup / auditing / TTL jobs
CREATE INDEX IF NOT EXISTS idx_replay_guard_issued_at
    ON replay_guard (issued_at);

COMMENT ON TABLE replay_guard IS
'Stateful replay protection table.
Insert conflict = replay or duplicate.
Cleanup is time-based and external.';


-- ============================================================================
-- EVENT LINKS (CAUSALITY / DERIVATION GRAPH)
-- ============================================================================
-- Optional graph of event relationships.
-- Purely informational.
-- No business logic implied.
-- ============================================================================

CREATE TABLE IF NOT EXISTS event_links (
    parent_id   UUID NOT NULL,
    child_id    UUID NOT NULL,
    relation    TEXT NOT NULL,

    PRIMARY KEY (parent_id, child_id),

    CONSTRAINT fk_event_links_parent
        FOREIGN KEY (parent_id) REFERENCES events (id)
        ON DELETE CASCADE,

    CONSTRAINT fk_event_links_child
        FOREIGN KEY (child_id) REFERENCES events (id)
        ON DELETE CASCADE
);


-- ============================================================================
-- DELIVERY STATE (CHARON VESSEL RESPONSIBILITY)
-- ============================================================================
-- IMPORTANT:
-- - NOT part of Nekhebet Core trust model
-- - Tracks delivery AFTER event is committed
-- - Can be dropped / rebuilt safely
-- - All failures here MUST NOT affect event integrity
-- ============================================================================

CREATE TABLE IF NOT EXISTS delivery_state (
    event_id        UUID PRIMARY KEY,
    destination     TEXT NOT NULL,
    status          TEXT NOT NULL,      -- pending / sent / failed / dead
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,

    CONSTRAINT fk_delivery_event
        FOREIGN KEY (event_id) REFERENCES events (id)
        ON DELETE CASCADE
);

COMMENT ON TABLE delivery_state IS
'Transport-layer delivery tracking.
Owned by Charon Vessel.
Not part of cryptographic trust boundary.';


-- ============================================================================
-- METRICS & OBSERVABILITY (OUT-OF-BAND)
-- ============================================================================
-- Replay detection is surfaced via application-level metrics.
--
-- Contract:
-- - Any INSERT conflict on replay_guard MUST emit:
--     event_type = "seth.caught"
-- - Storage layer MUST NOT aggregate or count metrics internally
-- - Observability is handled in ingest / verify layer
--
-- This avoids:
-- - Side-channel state
-- - Hidden counters
-- - Security theater inside the database
-- ============================================================================


-- ============================================================================
-- CLEANUP JOBS (EXTERNAL, OPTIONAL)
-- ============================================================================
-- Replay guard retention policy example:
--
-- DELETE FROM replay_guard
-- WHERE issued_at < now() - interval '7 days';
--
-- Notes:
-- - Retention window depends on threat model
-- - Cleanup MUST be monotonic and idempotent
-- - Safe to run concurrently with ingest
-- ============================================================================


-- ============================================================================
-- NOTES
-- ============================================================================
-- 1. No payload-level indexing on purpose
--    → payload is opaque, trust boundary is envelope
--
-- 2. No UPDATEs on events or replay_guard
--    → append-only invariant
--
-- 3. replay_guard is the ONLY stateful security table
--
-- 4. Schema is compatible with:
--    - PostgreSQL only
--    - PostgreSQL + LMDB (hybrid)
--    - File / object storage via Charon Vessel
--
-- 5. All security decisions are explicit and auditable
-- ============================================================================
