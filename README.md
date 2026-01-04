### Nekhebet: Tamper-Evident Signed Event Platform

**Nekhebet** — модульная платформа для сбора, подписывания, хранения и верификации событий с криптографическими гарантиями целостности, подлинности и защиты от повторного воспроизведения. Система спроектирована вокруг принципов **append-only immutable log**, **zero-trust verification** и **defense-in-depth**, что делает её пригодной для аудита, compliance, форензики и долговременной архивации чувствительных данных.

Версия **v4.0.0** реализована как монорепозиторий с тремя чётко разделёнными пакетами:
- **`nekhebet-core`** — криптографическое и протокольное ядро.
- **`nekhebet-store`** — слой неизменяемого хранения и replay‑контроля.
- **`nekhebet-ingest`** — ingest‑пайплайны и адаптеры источников (включая демонстрационный Telegram‑адаптер).

---

## 1. nekhebet-core — Cryptographic & Protocol Core

`nekhebet-core` является каноническим источником истины для формата событий и правил их валидации. Пакет не зависит от внешних библиотек хранения или транспорта и может использоваться автономно.

### Основные возможности

- **Canonical serialization (RFC 8785, JCS)**  
  Детерминированная каноникализация JSON гарантирует идентичный хэш одного и того же события независимо от порядка ключей, реализации JSON или платформы.

- **Ed25519 signatures**  
  Подпись вычисляется над канонизированным заголовком события, включающим криптографический хэш payload (SHA‑256).

- **Replay protection**  
  Защита от повторных атак на основе `(key_id, nonce, issued_at)` с политиками, зависящими от типа события.

- **Strict zero‑trust verification**  
  Любое событие — даже созданное внутри системы — проходит полную верификацию: подпись, хэши, срок действия, replay‑контроль, ограничения размеров.

- **DoS hardening**  
  Жёсткие лимиты на размер payload, глубину структур, nonce и метаданные.

- **Event registry**  
  Явно зарегистрированные типы событий (например, `omen.observed`, `seth.caught`) с политиками безопасности и допустимыми параметрами.

- **Reference replay guard & metrics**  
  In‑memory реализация для тестирования и локальной валидации.

`nekhebet-core` задаёт протокол и криптографические гарантии всей экосистемы.

---

## 2. nekhebet-store — Persistent Immutable Storage

`nekhebet-store` реализует долговременное хранение подписанных событий без ослабления криптографических свойств.

### Поддерживаемые режимы хранения

- **PostgreSQL**  
  Авторитетный replay guard, транзакционные гарантии и индексация по метаданным.

- **LMDB**  
  Высокопроизводительное mmap‑хранилище для быстрых чтений по `content_hash`.

- **Hybrid (рекомендуемый для production)**  
  PostgreSQL как authoritative metadata store + LMDB как blob‑store. Последовательность операций: *PG first → LMDB*, обеспечивающая логическую атомарность.

### Гарантии хранения

- **Append‑only**: операции UPDATE/DELETE над событиями отсутствуют.
- **Idempotency**: защита от дубликатов по `content_hash` и `(key_id, nonce)`.
- **Tamper detection**: любое расхождение подписи или хэша обнаруживается при чтении.
- **Opaque payload**: содержимое payload не интерпретируется и не индексируется.
- **Подготовка к delivery layer**: схемы `delivery_state` и метаданные для будущих транспортов.

Контракт‑тесты подтверждают корректное отклонение replay‑атак, обнаружение tampering и согласованность hybrid‑режима.

---

## 3. nekhebet-ingest — Ingest Pipelines

`nekhebet-ingest` отвечает за ввод событий из внешних источников и намеренно не содержит бизнес‑логики хранения или верификации.

### Telegram adapter (демонстрационный)

- Подключается к указанному чату через Telethon.
- Преобразует сообщения в детерминированный payload (текст, автор, media‑metadata, metrics, flags).
- Формирует unsigned envelope типа `omen.observed`.
- Подписывает событие и сохраняет его в storage.

Адаптер **stateless** и служит примером реального источника. Архитектура допускает добавление HTTP‑endpoint’ов, Kafka‑consumer’ов, WebSocket‑stream’ов и файловых источников без изменения core.

---

## Архитектурные принципы

- **Tamper‑evident log** — каждое событие криптографически связано со своим содержимым.
- **Explicit trust boundaries** — ingest, signing, verification и storage разделены.
- **Replay‑safety by design** — защита встроена на уровне протокола.
- **Extensibility** — новые адаптеры, distributed replay guard, verification tools и аналитика добавляются без изменения ядра.
- **Production readiness** — async‑pipeline, graceful shutdown, hybrid‑storage для high‑throughput сценариев.

---

## Пример использования

1. Настроить `.env` (Telegram API, PostgreSQL, приватный ключ Ed25519 в base64).
2. Запустить `nekhebet-telegram`.
3. Система начинает архивировать события в tamper‑evident журнал.
4. Любое событие может быть независимо верифицировано через API `nekhebet-core`.

---

**Nekhebet** — это не архиватор конкретного источника, а универсальная платформа для систем, где требуется криптографически доказуемая история событий: аудит, compliance, расследования, event sourcing и доверенные журналы.

Открыт для расширения: новые адаптеры, инструменты верификации и улучшения безопасности. 
Лицензия: MIT (planned). 
Python ≥ 3.11.


---

## Архитектурная диаграмма (логическая)

```
                ┌──────────────────────────────┐
                │        External Sources       │
                │ (Telegram, HTTP, Kafka, etc.) │
                └───────────────┬──────────────┘
                                │
                                ▼
                ┌──────────────────────────────┐
                │        Ingest Adapters        │
                │  (stateless, transport-only) │
                │  nekhebet-ingest              │
                └───────────────┬──────────────┘
                                │ unsigned envelope
                                ▼
                ┌──────────────────────────────┐
                │     Signing Boundary          │
                │  Ed25519, nonce, issued_at   │
                │  nekhebet-core                │
                └───────────────┬──────────────┘
                                │ signed envelope
                                ▼
                ┌──────────────────────────────┐
                │   Verification Boundary       │
                │  hash / signature / replay   │
                │  nekhebet-core                │
                └───────────────┬──────────────┘
                                │ verified event
                                ▼
        ┌────────────────────────────────────────────┐
        │           Immutable Storage Layer           │
        │            nekhebet-store                   │
        │                                            │
        │   ┌──────────────┐    ┌─────────────────┐ │
        │   │ PostgreSQL   │    │      LMDB       │ │
        │   │ metadata +   │    │ content blobs   │ │
        │   │ replay guard │    │ mmap reads      │ │
        │   └──────┬───────┘    └─────────┬───────┘ │
        │          │   PG first → LMDB     │         │
        └──────────┴──────────────────────┴─────────┘
                                │
                                ▼
                ┌──────────────────────────────┐
                │     Verification / Export    │
                │  Audit, analytics, replay    │
                │  (future tools)              │
                └──────────────────────────────┘
```

**Trust boundaries** выделены явно:
- External Source → Ingest
- Ingest → Signing
- Signing → Verification
- Verification → Storage

Каждый переход сопровождается полной криптографической проверкой.

---

## Threat Model (краткий)

Модель угроз ориентирована на **tamper-evidence**, а не на сокрытие данных.

### 1. Подмена или модификация события (Tampering)

**Угроза:** изменение payload или metadata после приёма.

**Защита:**
- SHA-256 хэш payload включён в подписываемый заголовок.
- Ed25519-подпись проверяется при каждом чтении.
- Любое расхождение → событие считается недействительным.

---

### 2. Replay-атаки

**Угроза:** повторная отправка ранее валидного события.

**Защита:**
- `(key_id, nonce)` uniqueness.
- `issued_at` + TTL-политики.
- Replay guard в storage (authoritative).

---

### 3. Подмена источника (Impersonation)

**Угроза:** злоумышленник выдаёт себя за легитимный ingest.

**Защита:**
- Каждому источнику соответствует собственный `key_id`.
- Подписи верифицируются без доверия к transport.
- Zero-trust: «внутренние» события не считаются доверенными априори.

---

### 4. DoS / Resource Exhaustion

**Угроза:** перегрузка системы большими или глубоко вложенными payload.

**Защита:**
- Жёсткие лимиты размера и глубины payload.
- Ограничения на nonce и metadata.
- O(1) replay checks в storage.

---

### 5. Storage Compromise

**Угроза:** атакующий получает доступ к базе данных.

**Защита:**
- Storage не является trust anchor.
- Любое чтение требует верификации подписи и хэша.
- Payload хранится как opaque blob.

---

### 6. Insider Threat

**Угроза:** легитимный оператор пытается изменить историю.

**Защита:**
- Append-only модель.
- Отсутствие UPDATE/DELETE.
- Криптографическая связность событий с origin key.

---

### Threats intentionally out of scope

- Конфиденциальность payload (encryption-at-rest).
- Traffic analysis.
- Compromise приватных ключей источника.

Эти аспекты могут быть добавлены поверх протокола, не изменяя `nekhebet-core`.

