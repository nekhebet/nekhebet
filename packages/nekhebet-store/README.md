# Nekhebet Store
**Append-Only хранилище верифицируемых событий**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue)](schema.sql)
[![LMDB](https://img.shields.io/badge/LMDB-1.4+-orange)](https://www.symas.com/lmdb)
[![nekhebet-core](https://img.shields.io/badge/depends-on%20nekhebet--core%204.0+-9cf)](https://pypi.org/project/nekhebet-core/)

Nekhebet Store — высокопроизводительное append-only хранилище для подписанных событий Nekhebet.

Обеспечивает атомарное сохранение, idempotency по content_hash и replay-защиту по (key_id, nonce).

Гибридный режим: PostgreSQL (метаданные, аналитика) + LMDB (быстрый доступ к полным envelope).

## Ключевые гарантии

- Строго append-only — события никогда не модифицируются/удаляются
- Idempotency по SHA-256 payload
- Replay protection на уровне хранилища
- Атомарность: PG пишется первым
- Zero-trust: store не верифицирует подпись (только core)

## Компоненты

- **PGEventRepository** — PostgreSQL (авторитетный индекс)
- **LMDBEventRepository** — mmap blob-store
- **HybridEventRepository** — комбинированный (рекомендуемый)

## Установка

```bash
pip install nekhebet-store
```

## Быстрый старт (Hybrid)

```python
import psycopg2
from nekhebet_store import HybridEventRepository
from nekhebet_core import SignedEnvelope  # ваш подписанный envelope

conn = psycopg2.connect(dsn="dbname=nekhebet user=postgres")
repo = HybridEventRepository(pg_conn=conn, lmdb_path="/var/lib/nekhebet/lmdb")

repo.save(your_signed_envelope)
fetched = repo.get("event-id-uuid")
repo.close()
```

Схема БД: см. `schema.sql`

## Лицензия

MIT License

## Краткое резюме

Nekhebet Store гарантирует: каждое записанное событие — подлинное, уникальное и неизменное навсегда.

Если событие в store — оно математически доказуемо настоящее.
