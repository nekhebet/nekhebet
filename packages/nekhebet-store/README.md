# Nekhebet Store

**Append-only хранилище верифицируемых событий**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue)](schema.sql)
[![LMDB](https://img.shields.io/badge/LMDB-1.4+-orange)](https://www.symas.com/lmdb)
[![nekhebet-core](https://img.shields.io/badge/depends-on%20nekhebet--core%204.0+-9cf)](https://pypi.org/project/nekhebet-core/)

Nekhebet Store — высокопроизводительное append-only хранилище для подписанных событий Nekhebet.  
Store не проверяет криптографию (это делает nekhebet-core), но гарантирует атомарность, idempotency и replay-защиту.

## Ключевые гарантии
- Строго append-only — события никогда не модифицируются и не удаляются
- Idempotency по SHA-256 хэшу payload
- Replay-защита по паре (key_id, nonce)
- Атомарность: PostgreSQL пишется первым
- Zero-trust: store не верифицирует подпись

## Архитектура
```
PostgreSQL (метаданные + авторитетный индекс)
        +
LMDB (полные SignedEnvelope, mmap-доступ)
```

PostgreSQL — источник истины для метаданных и индексов.  
LMDB — оптимизированный blob-store для быстрого чтения полных envelope.

## Компоненты
- **PGEventRepository** — чистый PostgreSQL (метаданные + индексы)
- **LMDBEventRepository** — чистый LMDB (быстрый blob-store)
- **HybridEventRepository** — комбинированный режим (рекомендуемый для production)

## Быстрый старт (Hybrid)
```python
import psycopg2
from nekhebet_store import HybridEventRepository

conn = psycopg2.connect("dbname=nekhebet user=postgres")
repo = HybridEventRepository(pg_conn=conn, lmdb_path="/var/lib/nekhebet/lmdb")
repo.save(your_signed_envelope)
fetched = repo.get("event-id-uuid")
repo.close()
```

Схема БД: см. `schema.sql`

## Установка
```bash
pip install nekhebet-store
```

Требования:  
Python 3.11+  
PostgreSQL 16+  
LMDB 1.4+

## Лицензия
MIT License


## Кратко

**Nekhebet Store — это память.
Она ничего не решает.
Она просто не забывает.**
