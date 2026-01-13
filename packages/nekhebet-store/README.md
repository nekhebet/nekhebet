# Nekhebet Store
**Append-Only Cryptographically Verifiable Event Storage**

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue)
![LMDB](https://img.shields.io/badge/LMDB-1.4+-orange)
![nekhebet-core](https://img.shields.io/badge/depends-on%20nekhebet--core%204.0+-9cf)

## 🔺 Обзор

**Nekhebet Store** — это высокопроизводительное, строго append-only хранилище для **криптографически верифицируемых событий** Nekhebet.

Оно отвечает за:

- атомарное сохранение подписанных конвертов (`SignedEnvelope`)
- **idempotency** по `content_hash` (payload SHA-256)
- **replay protection** на уровне хранилища `(key_id, nonce)`
- быструю выборку по `event_id` и `content_hash`
- гибридный режим **PostgreSQL + LMDB** для максимальной производительности и надёжности

Store **не доверяет** никаким данным, которые не прошли полную верификацию в `nekhebet-core`.  
Всё, что попало в хранилище — **математически доказуемо подлинно**.

## 🔺 Ключевой инвариант

> Хранилище **никогда** не модифицирует и не удаляет уже записанные события.  
> Единственное исключение — **реplay protection** (отклонение дубликатов).

## 🔺 Архитектура хранилища

```
Ingest / Verification (nekhebet-core)
           ↓
   HybridEventRepository
      /               \
PostgreSQL           LMDB
(metadata +          (full opaque
 replay guard)       SignedEnvelope blobs)
```

- **PostgreSQL** — **авторитетный источник**:
  - replay protection
  - метаданные (id, type, issued_at, source, content_hash)
  - индексы для аналитики и поиска

- **LMDB** — **быстрый mmap-доступ**:
  - хранение полных подписанных конвертов
  - O(1) чтение по content_hash
  - zero-copy итерация

- **HybridEventRepository** — логически атомарный слой:
  - Сначала пишет в PostgreSQL (критично)
  - Только потом в LMDB (оптимизация)

## 🔺 Установка

```bash
# Рекомендуемый способ
pip install nekhebet-store
```

```bash
# Репозиторий
pip install git+https://github.com/nekhebet/nekhebet-store.git@main
```

```bash
# Для разработки и тестов
git clone https://github.com/nekhebet/nekhebet-store.git
cd nekhebet-store
pip install -e ".[dev]"
```

Зависимости (автоматически):
- `nekhebet-core>=4.0.0`
- `psycopg2-binary>=2.9` — PostgreSQL
- `lmdb>=1.4.1` — LMDB

Требуется **Python 3.10+**.

## 🔺 Пример использования

```python
from psycopg2 import connect
from nekhebet_store import HybridEventRepository
from nekhebet_core import verify_envelope

# PostgreSQL подключение
pg_conn = connect(
    dbname="nekhebet",
    user="postgres",
    password="",
    host="localhost",
    port=5432
)

# Путь к LMDB (директория должна существовать)
lmdb_path = "/var/lib/nekhebet/lmdb"

repo = HybridEventRepository(pg_conn, lmdb_path)

# Сохранение верифицированного события
repo.save(signed_envelope)  # атомарно: PG → LMDB

# Получение по event_id
envelope = repo.get("550e8400-e29b-41d4-a716-446655440000")

# Проверка (всегда рекомендуется)
result = verify_envelope(envelope)
assert result.valid

# Закрытие (опционально)
repo.close()
```

## 🔺 Основные реализации

- **`pg_repository.py`** — PostgreSQL (авторитетный индекс + replay guard)
- **`lmdb_repository.py`** — LMDB (быстрое хранение полных конвертов)
- **`hybrid_repository.py`** — гибридный слой (логическая атомарность)
- **`schema.sql`** — полная схема PostgreSQL (append-only, replay guard)

## 🔺 Инварианты безопасности

1. **Append-only** — нет UPDATE/DELETE на `events`
2. **Idempotency** — дубликаты по `content_hash` отклоняются
3. **Replay protection** — `(key_id, nonce)` уникален навсегда
4. **Zero-trust** — Store не верифицирует подпись, полагается только на `nekhebet-core`
5. **Гибридная согласованность** — PG всегда пишется первым
6. **Атомарность** — если PG успех → LMDB должен тоже успеть (иначе критическая ошибка)

## 🔺 Очистка replay guard

```sql
-- Пример: PostgreSQL
DELETE FROM replay_guard
WHERE issued_at < now() - interval '7 days';

-- LMDB (через API)
repo.lmdb.cleanup_replay_guard(older_than_iso="2025-01-01T00:00:00Z")
```

## 🔺 Лицензия

MIT

## 🔺 Краткое резюме

**Nekhebet Store** — это высокопроизводительное, строго append-only хранилище, которое гарантирует:

> Каждое записанное событие — **математически доказуемо подлинно**, уникально и неизменно.

PostgreSQL обеспечивает надёжность и аналитику, LMDB — молниеносный доступ к полным конвертам, а гибридный слой — максимальную производительность без потери безопасности.

Если событие попало в Store — оно **навсегда** подлинное.  
