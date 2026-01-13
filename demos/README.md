# Nekhebet Omen Display
**Verifiable Real-Time Event Display Pipeline**

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
      **Live демо**: http://0808.us.nekhebet.su:8080
    </td>
  </tr>
</table>

## **Управление**
**Медиа из выбранных источников Telegram**
   - Фото, видео (клик по видео = включить/выключить звук)
   - Специальные медиа (список/метка) могут вызывать вспышки экрана
   - Автоматическая смена каждые ~5.5 секунд
```
[■] AUTO (5)
```
- **Нажатие** — приостановить/возобновить автоматическую смену медиа
- **Цифра** — отсчёт секунд до следующей смены
- **Индикатор**:
  - 🟢 (зелёный) — автопереключение активно
  - 🟡 (жёлтый) — режим паузы

```
[▶] NEXT
```
- Ручной переход к следующему медиа
- Свайп на мобильных

```
[↻] RESET (0)
```
- **Очередь сообщений**: до 100 сообщений
- **Цифра** — количество сообщений в очереди
- Нажатие - полный сброс 
- Очищает очередь сообщений и медиа
- **Красный индикатор** — после нажатия

***Еще***

- **Свайп влево** = кнопка NEXT
- **Нажатие на облако слов** = полная остановка воспроизведения медиа и сообщений

**Текст (Typewriter)**
   - Ключевые слова подсвечиваются анимацией
   - В начале каждой строки — цветные сегменты (индикаторы источника)

## Общее назначение 

Nekhebet Omen Display — демонстрация реализации end-to-end пайплайна для криптографически верифицируемого сбора, хранения и отображения событий из Telegram в реальном времени.

Решает задачу:

- Надёжного приёма сообщений и медиа из выбранных источников
- Криптографической защиты целостности и аутентичности каждого события
- Безопасного хранения с replay-защитой
- Живой визуализации: typewriter-текст, слайды медиа, word cloud, UX-контроли
- Работы в режиме арт-инсталляции / информационной панели

Ключевой инвариант — **каждое отображаемое событие криптографически проверяемо** через Nekhebet core (Ed25519 + JCS-канонизация).

## 🔺 Архитектура

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

Дополнительно: **Charon Vessel** (отдельный native-демон) может использоваться для безопасной ротации медиа-файлов (cross-device, race-protected).

## 🔺 Границы ответственности

**Ingest Layer** (Python/Telethon)
- Приём новых сообщений в реальном времени
- Скачивание медиа (параллельно, semaphore)
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

## 🔺 Сетевые интерфейсы

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
- `GET /phrases.json` — idle-режим

## 🔺 Типы сообщений (Server → Client)

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

## Синхронизация медиа

- Ingest скачивает медиа
- Server периодически синхронизирует директорию (старые перемещаются в media)
- БД media_files обновляется
- Клиент получает уведомление → добавляет в priorityQueue (если special_id) или newMediaQueue
- Файловая система — источник истины

## Облако слов (end-to-end)

```
Telegram → Ingest → SignedEnvelope → Store
                          ↓
PostgreSQL NOTIFY → Server.generateWordCloud() → WS payload.wordCloud → Client.renderWordCloud()
```

- Генерация только на сервере (stopword, частотный анализ)
- Клиент — чистый рендер

## Модель состояний (сквозная)

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

## 🔺 Поток основного цикла

```
[Ingest]
New Telegram message → download media → create/sign envelope → store.save()
                                                      ↓
PostgreSQL NOTIFY → Server → verify → wordCloud → WS.send()
                                                      ↓
[Client]
enqueue → Typewriter → MediaSlides.nextSlide() → renderWordCloud()
```

## 🔺 Защита и устойчивость

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
- Одинаковый порядок у разных клиентов

Приоритет — плавность UX и стабильность инсталляции.

## 🔺 Инварианты системы

1. Каждое отображаемое событие проходит полную Nekhebet-верификацию
2. Подпись фиксирована: Ed25519 + JCS (RFC 8785)
3. Медиа-файлы никогда не модифицируются после скачивания
4. Сервер не управляет UI-состоянием клиента
5. Клиент деградирует грациозно при потере соединения

## 🔺 Заключение

Nekhebet Omen Display — это пайплайн, сочетающий криптографическую надёжность Nekhebet с живой визуализацией потоковых событий. Система предназначена для длительных инсталляций.
рхитектура полностью открыта для аудита.
