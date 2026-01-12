# Nekhebet Omen Display — Verifiable Real-Time Event Display Pipeline

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Node.js](https://img.shields.io/badge/nodejs-20-blue)
![Security](https://img.shields.io/badge/security-cryptographically%20verifiable-brightgreen)

<table class="mobile-table">
  <tr>
    <td colspan="2" class="mobile-main">
      <p> <img src="https://i.postimg.cc/qvRwVDvL/080808.png" alt="Описание" width="100%" /></p>
    </td>
  </tr>
  <tr>
    <td colspan="2" class="mobile-side">
    </td>
  </tr>
</table>

**Живое демо**: [0808.us.nekhebet.su:8080](http://0808.us.nekhebet.su:8080)

## 🎯 Общее назначение системы

Nekhebet Omen Display — это полный end-to-end пайплайн для криптографически верифицируемого сбора, хранения и отображения событий из Telegram в реальном времени.

Система решает задачу:

- Надёжного приёма сообщений и медиа из публичных/приватных чатов
- Криптографической защиты целостности и аутентичности каждого события
- Безопасного хранения с replay-защитой
- Живой визуализации: typewriter-текст, слайды медиа, word cloud, UX-контроли
- Работы в режиме арт-инсталляции / информационной панели

Ключевой инвариант — **каждое отображаемое событие криптографически проверяемо** через Nekhebet core (Ed25519 + JCS-канонизация).

## 🧱 Высокоуровневая архитектура

```
┌──────────────────────────────┐
│          Telegram             │
│   (chats / channels)         │
└──────────────┬───────────────┘
               │ Telethon
┌──────────────▼───────────────┐
│        INGEST LAYER          │
│  (realtime_recorder.py)      │
│ • Stateless adapter          │
│ • Media download (parallel)  │
│ • Unsigned → Signed envelope │
└──────────────┬───────────────┘
               │ save(signed)
┌──────────────▼───────────────┐
│     NEKHEBET STORE           │
│  Hybrid Repository           │
│ • PostgreSQL (indexes)       │
│ • LMDB (append-only blobs)   │
└──────────────┬───────────────┘
               │ LISTEN/NOTIFY
┌──────────────▼───────────────┐
│          SERVER              │
│   (server.js)                │
│ • Verification (replay guard)│
│ • WordCloud generation       │
│ • Media sync (newtg → media) │
│ • WebSocket push             │
└──────────────┬───────────────┘
               │ WS + HTTP
┌──────────────▼───────────────┐
│          CLIENT              │
│   (script.js + HTML)         │
│ • Typewriter animation       │
│ • MediaSlides carousel       │
│ • WordCloud renderer         │
│ • Controls (pause/reset)     │
└──────────────────────────────┘
```

Дополнительно: **Charon Vessel** (отдельный native-демон) может использоваться для безопасной ротации медиа-файлов в `/private/media` (cross-device, race-protected).

## 🔌 Границы ответственности

**Ingest Layer** (Python/Telethon)
- Приём новых сообщений в реальном времени
- Скачивание медиа (параллельно, semaphore=5)
- Создание unsigned envelope
- Подпись через Nekhebet DefaultSigningContext
- Сохранение в HybridEventRepository
- НЕ знает о дисплее

**Nekhebet Store** (hybrid PG+LMDB)
- Источник истины для событий
- Replay-защита через (key_id, nonce, issued_at)
- Детерминированная верификация
- PostgreSQL NOTIFY на новые события

**Server** (Node.js)
- Слушает PostgreSQL NOTIFY
- Полная верификация signed envelope (Nekhebet core порт или эквивалент)
- Генерация word cloud (stopword removal)
- Приоритизация (special_id из config)
- Синхронизация медиа-директорий (newtg лимит 25 → media)
- Push через WebSocket
- Throttling, heartbeat, backpressure protection

**Client** (Browser JS)
- Визуализация и UX
- Очереди сообщений и медиа
- Анимации (typewriter, slides)
- Локальный fallback (phrases.json при отсутствии событий)
- Управление состояниями (pause, reset, manual next)

## 📡 Сетевые интерфейсы

**WebSocket**
```
ws://omen.nekhebet.live:8080
```
- Направление: server → client только
- Push новых сообщений и медиа

**HTTP API** (для клиента)
- `GET /media-files?page=N` — пагинированные медиа
- `GET /new-media-files` — новые файлы (fallback)
- `GET /media/:id` — прямой доступ к файлу
- `GET /phrases.json` — локальные фразы для idle-режима

## 📨 Типы сообщений (Server → Client)

1. **Message**
```json
{
  "type": "message",
  "text": "Сообщение...",
  "date": "2026-01-11T12:00:00Z",
  "wordCloud": [{"word": "ключевое", "freq": 12}, ...],
  "special_id": "1"
}
```
- wordCloud генерируется на сервере из верифицированного payload

2. **New Media**
```json
{
  "type": "new_media",
  "id": "abc123",
  "file_type": "mp4",
  "mtime": 1734000000,
  "special_id": "2"
}
```

## 🎞 Синхронизация медиа

- Ingest скачивает медиа в `/private/newtg` (лимит 25 файлов)
- Server периодически (каждые 2 мин) синхронизирует:
  - newtg → media/new (старые перемещаются в media)
  - БД media_files обновляется
- Клиент получает уведомление → добавляет в priorityQueue (если special_id) или newMediaQueue
- Файловая система — источник истины

## ☁️ Облако слов (end-to-end)

```
Telegram → Ingest → SignedEnvelope → Store
                          ↓
PostgreSQL NOTIFY → Server.generateWordCloud() → WS payload.wordCloud → Client.renderWordCloud()
```

- Генерация только на сервере (stopword, частотный анализ)
- Клиент — чистый рендер
- Может отставать от текущего сообщения (допустимо)

## 🧠 Модель состояний (сквозная)

**Client**
- `isPaused` / `isWordCloudPaused`
- `isAnimating`
- `isLocalPhraseMode` (fallback при отсутствии событий)

**Server**
- Stateless по отношению к клиентам
- Best-effort delivery

## ⏸ Паузы и управление

- Все паузы — только на клиенте
- Сервер продолжает слать сообщения
- Reset — очищает очереди, переподключает WS, возвращает в локальный режим

## 🔁 Поток основного цикла

```
[Ingest]
New Telegram message → download media → create/sign envelope → store.save()
                                                      ↓
PostgreSQL NOTIFY → Server → verify → wordCloud → WS.send()
                                                      ↓
[Client]
enqueue → Typewriter → MediaSlides.nextSlide() → renderWordCloud()
```

## 🛡 Защита и устойчивость

**Ingest**
- Semaphore на скачивание
- FloodWait handling
- Graceful shutdown

**Store**
- Криптографическая верификация
- Replay guard

**Server**
- Throttling 500ms/client
- WS heartbeat + ping/pong
- Backpressure check
- Retry на PostgreSQL ошибках

**Client**
- Graceful анимации stop
- Ignore duplicate/slide flags
- Fallback на локальные фразы

## ⚠️ Сквозные не-гарантии

Система осознанно НЕ гарантирует:
- Строгую синхронность текста и медиа
- Доставку 100% событий всем клиентам
- Одинаковый порядок у разных клиентов
- Мгновенную реакцию на reset/pause

Приоритет — плавность UX и стабильность инсталляции.

## 📐 Инварианты системы

1. Каждое отображаемое событие проходит полную Nekhebet-верификацию
2. Подпись фиксирована: Ed25519 + JCS (RFC 8785)
3. Медиа-файлы никогда не модифицируются после скачивания
4. Сервер не управляет UI-состоянием клиента
5. Клиент деградирует грациозно при потере соединения

## 🏁 Заключение

Nekhebet Omen Display — это production-ready пайплайн, сочетающий криптографическую надёжность Nekhebet с живой визуализацией потоковых событий. Система работает в продакшене с 2025 года и предназначена для длительных инсталляций.

Лицензия: MIT (ядро), proprietary (ingest + display компоненты).

Исходный код закрыт, но архитектура полностью открыта для аудита.
