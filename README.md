# Nekhebet 
**🔺 Nekhebet Omen Display — Verifiable Real-Time Event Display Pipeline**

![Python](https://img.shields.io/badge/python-3.11-blue)
![Node.js](https://img.shields.io/badge/nodejs-20-blue)
![Security](https://img.shields.io/badge/security-cryptographically%20verifiable-brightgreen)

Nekhebet Omen Display — демонстрация реализации end-to-end пайплайна для криптографически верифицируемого сбора, хранения и отображения событий из Telegram в реальном времени.

**🔺 Charon Vessel - Secure File Rotation Daemon**

![C++17](https://img.shields.io/badge/C++-17-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20FreeBSD-blue)
![Single Binary](https://img.shields.io/badge/single-binary-lightgrey.svg)

Charon Vessel — демон ротации файлов для Linux и FreeBSD с **атомарными операциями** и строгой защитой от race-condition атак, для надёжного и предсказуемого управления жизненным циклом файлов в условиях потенциально враждебной среды.

**🔺 Nekhebet Core · Store · Adapters - Cryptographically Verifiable Events**

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/codeql.yml?branch=main\&label=CodeQL)](https://github.com/nekhebet/nekhebet/actions/workflows/codeql.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main\&label=CI)](https://github.com/nekhebet/nekhebet/actions)

Nekhebet Core · Store · Adapters — реализация создания,
подписи и проверки криптографически проверяемых событий.

Определяет строгий формат контейнера событий
(**SignedEnvelope**) с канонической сериализацией,
криптографической подписью и детерминированной процедурой проверки.

## Какую задачу решает

В системах, где требуется
проверяемо установить, что:

- данные не были изменены,
- источник события аутентичен,
- повторное воспроизведение событий обнаруживается,
- проверка не зависит от среды выполнения или языка.

Типичные области применения:

- аудит и журналы событий,
- event-driven системы,
- приём данных из недоверенных источников,
- комплаенс и форензика,
- воспроизводимые конвейеры обработки данных.


## Модель данных

Каждое событие представлено в виде **SignedEnvelope**,
который состоит из трёх частей:

1. Канонический заголовок  
   (идентификаторы, временные метки, nonce, политики)
2. Полезная нагрузка  
   (произвольные доменные данные)
3. Криптографическая подпись

Подпись вычисляется **по каноническому представлению данных**,
а не по сериализации, зависящей от среды выполнения.


## Инварианты безопасности

Следующие свойства являются частью модели и не подлежат изменению:

- **Алгоритм подписи:** Ed25519
- **Хэш полезной нагрузки:** SHA-256
- **Канонизация:** RFC 8785 (JSON Canonicalization Scheme)
- **Модель доверия:** zero-trust
- **Защита от replay:** `(key_id, nonce, issued_at)`
- **Проверка:** полная и детерминированная

Эти инварианты зафиксированы на уровне протокола.


## Архитектура

### `nekhebet-core`

Самодостаточное ядро безопасности,
независимое от транспорта и хранилища.

Обязанности:

- определение канонической модели данных,
- детерминированная JSON-канонизация,
- создание и подписание контейнеров событий,
- строгая верификация подписей и структуры,
- защита от повторного воспроизведения,
- применение политик проверки.

Структура:

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


### Дополнительные компоненты

Следующие компоненты не являются частью ядра и подключаются отдельно:

- **Store** — постоянное хранилище (референс-дизайн для PostgreSQL / LMDB)
- **Ingest** — адаптеры для внешних источников данных


## Не является целью

Nekhebet **не является**:

- брокером сообщений,
- транспортным уровнем,
- бизнес-фреймворком,
- распределённой системой «из коробки».

Nekhebet представляет собой **протокольную и криптографическую основу**,
предназначенную для встраивания в другие системы.


## Статус

- Стабильная модель ядра
- Очерченные границы безопасности
- Развитие дополнительных компонентов

Интерфейсы могут эволюционировать,
инварианты безопасности — нет.


## Лицензия

MIT License


