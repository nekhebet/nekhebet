# Nekhebet Ingest
**Event ingestion adapters for zero-trust pipelines**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![Telethon](https://img.shields.io/badge/telegram-telethon-orange)](https://docs.telethon.dev/)
[![nekhebet-core](https://img.shields.io/badge/depends-on%20nekhebet--core%204.0+-9cf)](https://pypi.org/project/nekhebet-core/)
[![nekhebet-store](https://img.shields.io/badge/depends-on%20nekhebet--store%204.0+-9cf)](https://pypi.org/project/nekhebet-store/)

Nekhebet Ingest — слой приёма событий из внешних, недоверенных источников.  
Он подключается к внешним системам, извлекает события в реальном времени, нормализует их и передаёт в криптографический пайплайн Nekhebet.

Ingest **не принимает решений** и **ничему не доверяет**.  
Он лишь преобразует внешний сигнал в строго формализованное событие.

## Задача ingest-слоя
- Подключение к внешнему источнику
- Получение новых событий
- Детерминированное преобразование в payload
- Создание `UnsignedEnvelope` (nekhebet-core)
- Передача на подпись и сохранение

Ingest **не выполняет**:
- Криптографическую подпись
- Верификацию
- Хранение событий
- Управление ключами
- Бизнес-логику

Это сознательное ограничение архитектуры.

## Поддерживаемые источники
Текущая реализация:
- **Telegram** (каналы, группы, чаты) — reference-адаптер via Telethon

Возможные:
- Webhooks
- Kafka / RabbitMQ / SQS
- RSS / Atom
- Email (IMAP)
- Любые event-driven системы

## Архитектура пайплайна
```
External source (недоверенный)
        ↓
Ingest adapter
        ↓
Raw event → детерминированный payload
        ↓
create_envelope()          ← nekhebet-core
        ↓
sign_envelope()            ← nekhebet-core
        ↓
repo.save()                 ← nekhebet-store
```

Каждый этап изолирован.  
Доверие не передаётся между слоями.

## Установка
```bash
pip install nekhebet-ingest
```

Для разработки:
```bash
git clone https://github.com/nekhebet/nekhebet-ingest.git
cd nekhebet-ingest
pip install -e ".[dev]"
```

## Зависимости
- `nekhebet-core >= 4.0.0`
- `nekhebet-store >= 4.0.0`
- `telethon >= 1.34`
- `cryptography`
- `psycopg2-binary`
- `python-dotenv` (для .env в примерах)

Python 3.11+

## Конфигурация и запуск Telegram-адаптера
### .env пример
```env
TELEGRAM_API_ID=1234567
TELEGRAM_API_HASH=0123456789abcdef0123456789abcdef
TELEGRAM_CHAT_ID=-1001234567890
TELEGRAM_SOURCE=telegram-group-alpha

DB_HOST=localhost
DB_PORT=5432
DB_NAME=nekhebet
DB_USER=postgres
DB_PASSWORD=

NEKHEBET_KEY_ID=telegram-ingest-01
NEKHEBET_PRIVATE_KEY=ed25519_private_key_base64  # или путь к файлу

LMDB_PATH=/var/lib/nekhebet/lmdb
PG_DSN=postgresql://postgres:@localhost:5432/nekhebet  # альтернативно
```

### Запуск
```bash
nekhebet-ingest-telegram
```

или
```bash
python -m nekhebet_ingest.telegram.run
```

Graceful shutdown по SIGINT/SIGTERM.

## Формат payload (Telegram-пример)
```json
{
  "platform": "telegram",
  "chat_id": -1001234567890,
  "message_id": 12345,
  "date": "2026-01-13T09:45:12Z",
  "text": "Hello from Amsterdam!",
  "author": {
    "id": 987654321,
    "username": "nekhebet",
    "first_name": "Nekhebet",
    "last_name": null
  },
  "metrics": {
    "views": 42,
    "forwards": 3,
    "replies": 1
  },
  "flags": {
    "is_reply": false,
    "is_forward": false,
    "has_media": true
  },
  "media": [
    { "type": "photo", "file_id": "AgACAg..." }
  ]
}
```

Payload:
- Полностью детерминирован
- JSON-сериализуем
- Без бинарных данных (медиа — только метаданные)

## Ключевые инварианты
1. Ingest не хранит долговременное состояние (кроме сессии источника)
2. Payload всегда детерминирован и воспроизводим
3. Медиафайлы не загружаются — только идентификаторы
4. Подпись происходит **после** создания envelope
5. Все ошибки пробрасываются вверх
6. Внешний источник остаётся недоверенным на всех этапах

## Лицензия
MIT License

## Кратко
**Nekhebet Ingest — это входной шлюз в zero-trust систему.**  
Он ничего не доказывает.  
Он ничего не хранит.  

Он просто превращает внешний сигнал
в событие, которое дальше может быть доказано.
