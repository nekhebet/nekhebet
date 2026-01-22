# Nekhebet
**Zero-Trust Event System**  
*Cryptographic truth · Immutable memory · Real-time display*

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![C++17](https://img.shields.io/badge/C++-17-blue)
[![Node.js](https://img.shields.io/badge/Node.js-18+-blue?logo=node.js&logoColor=white)](https://nodejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue)](https://www.postgresql.org)
[![LMDB](https://img.shields.io/badge/LMDB-1.4+-orange)](https://www.symas.com/lmdb)

<!-- CI/CD badges (если настроены) -->
[![CI Core / Store](https://github.com/nekhebet/nekhebet/actions/workflows/ci.yml/badge.svg)](https://github.com/nekhebet/nekhebet/actions/workflows/ci.yml)
[![Charon Vessel CI/CD](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml)
[![CodeQL](https://github.com/nekhebet/nekhebet/actions/workflows/codeql.yml/badge.svg)](https://github.com/nekhebet/nekhebet/actions/workflows/codeql.yml)

## Содержание
- [Что такое Nekhebet](#что-такое-nekhebet)
- [Варианты реализации](#варианты-реализации)
- [Архитектурная модель](#архитектурная-модель)
- [Компоненты системы](#компоненты-системы)
- [Общая схема](#общая-схема)
- [Установка и тесты](#установка-и-тесты)
- [Компоненты подробнее](#компоненты-подробнее)
- [Модель безопасности](#модель-безопасности-кратко)
- [Чем Nekhebet не является](#чем-nekhebet-не-является)
- [Лицензия](#лицензия)

## Что такое Nekhebet
**Nekhebet** — минималистичная экосистема для **криптографически верифицируемой обработки событий** в недоверенной среде.

Ключевой принцип:
> **Ничто не считается подлинным, пока это не доказано криптографически.**  
> Прошло верификацию → существует.  
> Не прошло → не существует.

Это **криптографический фильтр**, а не message broker, SIEM или data lake.

## Варианты реализации
Когда нужны:
- zero-trust к источникам
- доказуемая подлинность событий
- неизменяемость истории
- аудитопригодность и воспроизводимость

**Типичные сценарии:**

- Forensic logging и audit trails
- Ingest из Telegram, API, сенсоров
- OSINT / situation room / мониторинг реального времени
- Digital signage / ambient display 24/7
- Compliance-heavy пайплайны

## Архитектурная модель
Жёсткие инварианты:
1. Zero-trust даже для локальных событий
2. Криптография выполняется до любой другой логики
3. Append-only семантика на уровне протокола
4. Каждый компонент делает одну вещь и делает её строго

## Компоненты системы
| Компонент          | Роль                        | Кратко                                              | Статус                  |
|--------------------|-----------------------------|-----------------------------------------------------|-------------------------|
| **Nekhebet Core**  | Криптографическое ядро      | Ed25519 подпись и zero-trust верификация            | ✅ Production-ready      |
| **Nekhebet Store** | Память                      | Append-only хранилище (PostgreSQL + LMDB)           | ✅ Production-ready      |
| **Omen Display**   | Визуализация                | Reference real-time display pipeline                | 🟡 Working prototype     |
| **Charon Vessel**  | Файловая надёжность         | Атомарная ротация и архивация файлов                | 🟡 High-reliability prototype |

## Общая схема
   ```markdown
   Недоверенные источники (Telegram, API, сенсоры)
           ↓
   Nekhebet Core (zero-trust проверка, Ed25519)
      ├─→ Отклонено
      └─→ Проверено
           ↓
   Nekhebet Store (PostgreSQL + LMDB, append-only)
      ├─→ LISTEN / NOTIFY
      │     ↓
      └─→ Omen Display (real-time, WebSocket, обогащение)
                 ↓
            Клиенты (24/7 ambient display)

      └─→ Charon Vessel (атомарная ротация файлов)
   ```

## Установка и тесты

```bash
git clone https://github.com/nekhebet/nekhebet.git
cd nekhebet

python -m venv .venv
source .venv/bin/activate   # или .venv\Scripts\activate на Windows

pip install -e ./packages/nekhebet-core
pip install -e ./nekhebet-store     # если нужен Store
```

### Запуск тестов безопасности (рекомендуется сразу)
```bash
# Тест ядра — подпись, верификация, replay, tampering, канонизация
python test_security_contract.py

# Тест хранилища — атомарность, idempotency, replay-защита (PG/LMDB/Hybrid)
python test_store_security_smoke.py
```

Ожидаемый успешный вывод:
```
OK. STORE SECURITY CONTRACT SATISFIED.
```

Тесты написаны как **самодостаточные smoke-контракты** (без pytest/unittest), чтобы их можно было запускать в минимальной среде.

### Production-установка
1. Клонируйте репозиторий
2. Установите нужные компоненты локально (см. выше)
3. Настройте PostgreSQL (для Store) и LMDB-путь
4. Спроектируйте управление ключами и nonce
5. Интегрируйте Core в ingest-пайплайн

Подробности — в README каждого компонента.

## Компоненты подробнее

### 🧠 Nekhebet Core  
Криптографическое ядро протокола
- Ed25519
- Канонический JSON (RFC 8785, JCS)
- Replay-защита по `(key_id, nonce)`
- Детерминированные ошибки верификации
- Zero-trust модель без исключений

➡ [`./packages/nekhebet-core`](./packages/nekhebet-core) · [PyPI](https://pypi.org/project/nekhebet-core/)

### 🗄 Nekhebet Store  
**Append-only память**
- PostgreSQL — авторитетный индекс и метаданные
- LMDB — быстрый immutable blob-store
- Idempotency по SHA-256
- Replay-защита на уровне хранилища
- Store не выполняет криптографию — только обеспечивает инварианты

➡ [`./nekhebet-store`](./nekhebet-store) · [PyPI](https://pypi.org/project/nekhebet-store/)

### 📺 Omen Display  
**Reference architecture real-time визуализации**

<table class="mobile-table">
  <tr>
    <td colspan="2" class="mobile-main">
      <p> <img src="https://i.postimg.cc/KcPmnF6f/0808-us-nekhebet-su.png" alt="Nekhebet Omen Display" width="100%" /></p>
    </td>
  </tr>
  <tr>
    <td colspan="2" class="mobile-side">
    </td>
  </tr>
</table>

- Ingest → enrich → distribute → render pipeline
- PostgreSQL LISTEN / NOTIFY для real-time событий
- WebSocket + backpressure management
- Vanilla JS клиент для 24/7 ambient display
- Graceful degradation и fallback-режимы

> **Примечание:** Omen Display — демонстрация архитектурных паттернов использования Core/Store.

➡ [`./omen-display`](./omen-display)

### ⚓ Charon Vessel  
**Secure Atomic File Rotation Daemon**

- Атомарные POSIX-операции (rename, link, copy_file_range)
- Защита от symlink, hardlink, TOCTOU атак
- Single binary, zero runtime dependencies
- Предсказуемость при сбоях и перезапусках

➡ [`./charon-vessel`](./charon-vessel)

## Модель безопасности (кратко)
**Защищает от**  
- подделки событий  
- replay-атак  
- tampering  
- race conditions  
- TOCTOU / symlink-атак  
- неявных изменений (канонизация)

**Не защищает от**  
- компрометации приватных ключей  
- DDoS на входе  
- физического доступа к серверу

## Чем Nekhebet не является
- ❌ Message broker  
- ❌ Blockchain  
- ❌ SIEM  
- ❌ Data lake  
- ❌ Бизнес-логикой  

**Nekhebet — инфраструктурный слой криптографического доверия.**

## Лицензия
MIT License — [LICENSE](LICENSE)
