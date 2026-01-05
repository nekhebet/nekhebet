# Nekhebet: Tamper-Evident Signed Event Platform
![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main&label=CI)](https://github.com/nekhebet/nekhebet/actions)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main&label=CodeQL&logo=github)](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml)
## Overview

**Nekhebet** — модульная платформа для сбора, подписывания, хранения и верификации событий с криптографическими гарантиями целостности, подлинности и защиты от повторного воспроизведения (**tamper-evidence**).  
Система спроектирована вокруг принципов **append-only immutable log**, **zero-trust cryptographic verification** и **defense-in-depth**, что делает её пригодной для аудита, compliance, форензики и долговременной архивации чувствительных данных.

Версия **v4.0.0** реализована как **монорепозиторий** с тремя чётко разделёнными пакетами:

- **`nekhebet-core`** — криптографическое и протокольное ядро.
- **`nekhebet-store`** — слой неизменяемого хранения и replay-контроля.
- **`nekhebet-ingest`** — ingest-пайплайны и адаптеры источников.

Python ≥ **3.11**

---

## Repository Structure

```text
nekhebet/
├── README.md
├── ARCHITECTURE.md
├── THREAT_MODEL.md
└── packages/
    ├── nekhebet-core/
    ├── nekhebet-store/
    └── nekhebet-ingest/
```

- `README.md` — high-level overview (этот файл)
- `ARCHITECTURE.md` — детальная архитектура и дизайн
- `THREAT_MODEL.md` — модель угроз и допущения безопасности

---

## Packages

### nekhebet-core

Каноническое криптографическое ядро системы.

Основные возможности:
- RFC 8785 (JCS) canonical JSON
- Ed25519 signatures
- Payload hashing (SHA-256)
- Replay protection `(key_id, nonce, issued_at)`
- Zero-trust verification
- Event registry и политики
- DoS hardening

`nekhebet-core` не зависит от storage или transport и может использоваться автономно.

---

### nekhebet-store

Persistent immutable storage для signed events.

Поддерживаемые режимы:
- PostgreSQL (authoritative replay guard)
- LMDB (high-performance blob store)
- Hybrid PG → LMDB (production recommended)

Гарантии:
- Append-only storage
- Idempotency
- Tamper detection
- Opaque payload

---

### nekhebet-ingest

Ingest-пайплайны для внешних источников.

Особенности:
- Stateless adapters
- Transport-only логика
- Демонстрационный Telegram-адаптер
- Простое расширение под HTTP, Kafka, WebSocket и файлы

---

## Architecture

Высокоуровневая архитектура и trust boundaries описаны в  
👉 **[ARCHITECTURE.md](ARCHITECTURE.md)**

Ключевые принципы:
- Explicit trust boundaries
- Cryptographic verification на каждом этапе
- Storage не является trust anchor

---

## Threat Model

Модель угроз, scope и out-of-scope аспекты описаны в  
👉 **[THREAT_MODEL.md](THREAT_MODEL.md)**

Фокус:
- Tampering
- Replay attacks
- Impersonation
- Storage compromise
- Insider threats

---

## Example Usage

1. Настроить `.env`:
   - Telegram API credentials
   - PostgreSQL connection
   - Ed25519 private key (base64)
2. Запустить ingest:
   ```bash
   nekhebet-telegram
   ```
3. События сохраняются в tamper-evident immutable log.
4. Любое событие может быть независимо верифицировано через `nekhebet-core`.

---

## Non-Goals

Следующие аспекты **осознанно не входят** в scope v4.0.0:
- Конфиденциальность payload (encryption-at-rest)
- Traffic analysis protection
- Key compromise mitigation
- Distributed clock synchronization

Эти возможности могут быть добавлены поверх протокола без изменения core.

---

## License

MIT (planned)

---

## Status

Проект находится в активной разработке.  
API `nekhebet-core` считается каноническим и стабильным для v4.x.

Contributions и security review приветствуются.
