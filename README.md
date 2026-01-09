
# Nekhebet — Cryptographically Verifiable Events

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/codeql.yml?branch=main\&label=CodeQL)](https://github.com/nekhebet/nekhebet/actions/workflows/codeql.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main\&label=CI)](https://github.com/nekhebet/nekhebet/actions)

**Nekhebet** — security-oriented protocol and reference implementation
for creating, signing and verifying **tamper-evident events**.

It provides a **cryptographically strict envelope format** (**SignedEnvelope**)
with deterministic serialization, replay protection and zero-trust verification.


## What problem it solves

Nekhebet is designed for systems where you must be able to **prove** that:

* data was not modified,
* the source of an event is authentic,
* replay attacks are prevented,
* verification is independent of runtime or language.

Typical use cases:

* audit logs,
* event-driven systems,
* data ingestion from untrusted sources,
* compliance / forensics,
* reproducible pipelines.


## Core model

Every event is a **SignedEnvelope**:

1. Canonical header (IDs, timestamps, nonce, policies)
2. Payload (arbitrary domain data)
3. Cryptographic signature

> 🔐 Signatures are calculated over a **canonical representation**,
> not over a runtime-dependent serialization.


## Security invariants

* **Signature:** Ed25519
* **Payload hash:** SHA-256
* **Canonicalization:** RFC 8785 (JCS)
* **Model:** Zero-trust (no trusted creation paths)
* **Replay protection:** `(key_id, nonce, issued_at)`
* **Verification:** always full, always deterministic

These invariants are **intentional and non-negotiable**.


## Architecture

### `nekhebet-core`

Self-contained security core, independent of transport or storage.

Responsibilities:

* canonical data model,
* deterministic JSON canonicalization,
* envelope creation & signing,
* strict verification pipeline,
* replay protection,
* policy enforcement.

```
nekhebet_core/
├── envelope.py
├── signing.py
├── verification.py
├── canonical.py
├── replay_guard.py
├── types.py
└── utils.py
```

### Optional components

* **Store** — persistent storage (PostgreSQL / LMDB reference design)
* **Ingest** — adapters for external data sources


## Non-Goals

Nekhebet is **not**:

* a message broker,
* a transport layer,
* a business framework,
* a distributed system out of the box.

It is a **security and protocol foundation** meant to be embedded.


## Status

* Stable core model
* Auditable security boundaries
* Actively evolving extensions

API surface may evolve,
**security invariants will not**.


## License

MIT


### TL;DR

If you need **cryptographically verifiable events** with
deterministic signatures and strict replay protection —
**Nekhebet is the core you build on.**

