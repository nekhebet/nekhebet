# Nekhebet Ingest
**Event Ingestion Adapters (Telegram + future sources)**

![Python](https://img.shields.io/badge/python-3.11+-blue)
![Telethon](https://img.shields.io/badge/telegram-telethon-orange)
![nekhebet-core](https://img.shields.io/badge/depends-on%20nekhebet--core%204.0+-9cf)
![nekhebet-store](https://img.shields.io/badge/depends-on%20nekhebet--store%204.0+-9cf)
![License](https://img.shields.io/badge/license-Proprietary-red)

## 🔺 Обзор

**Nekhebet Ingest** — это слой приёма событий из внешних источников с последующей нормализацией, созданием неподписанных конвертов и передачей их в подпись + хранилище.

На текущий момент адаптер — **Telegram** как пример (группы, каналы, чаты), но архитектура спроектирована для лёгкого добавления других источников (Webhooks, Kafka, SQS, RSS, email и т.д.).

Основные задачи адаптера:

- подключение к внешнему источнику
- получение новых событий в реальном времени
- преобразование в единый формат payload
- создание `UnsignedEnvelope` через `nekhebet-core`
- передача на подпись и сохранение в `nekhebet-store`

Адаптер **не выполняет** подпись, верификацию и хранение — он максимально лёгкий и stateless.

## 🔺 Архитектура ingest-пайплайна

```
External source
   (Telegram, Webhook, etc.)
         ↓
   Ingest Adapter
         ↓
   telegram_message → payload
         ↓
   create_envelope()   ← nekhebet-core
         ↓
   sign_envelope()     ← nekhebet-core
         ↓
   HybridEventRepository.save()  ← nekhebet-store
```

## 🔺 Установка

```bash
# Пока пакет приватный / в разработке
pip install git+https://github.com/nekhebet/nekhebet-ingest.git@main
```

```bash
# Для локальной разработки
git clone https://github.com/nekhebet/nekhebet-ingest.git
cd nekhebet-ingest
pip install -e ".[dev]"
```

Зависимости (автоматически):
- `nekhebet-core>=4.0.0`
- `nekhebet-store>=4.0.0`
- `telethon>=1.34`
- `python-dotenv`
- `psycopg2-binary`
- `cryptography`

Требуется **Python 3.11+**.

## 🔺 Запуск Telegram-адаптера

```bash
# 1. Создайте .env файл (пример)
cat > .env <<EOF
TELEGRAM_API_ID=1234567
TELEGRAM_API_HASH=0123456789abcdef0123456789abcdef
TELEGRAM_CHAT_ID=-1001234567890          # группа или канал
TELEGRAM_SOURCE=telegram-group-alpha

DB_HOST=localhost
DB_PORT=5432
DB_NAME=nekhebet
DB_USER=postgres
DB_PASSWORD=

NEKHEBET_KEY_ID=telegram-ingest-01
LMDB_PATH=/var/lib/nekhebet/lmdb
EOF
```

```bash
# 2. Запуск
python -m nekhebet_ingest.telegram.run
# или через poetry/pipx/uv:
nekhebet-telegram
```

Логирование идёт в stdout. При получении SIGINT/SIGTERM происходит graceful shutdown.

## 🔺 Структура payload (Telegram → Nekhebet)

```json
{
  "platform": "telegram",
  "chat_id": -1001234567890,
  "message_id": 12345,
  "date": "2026-01-13T09:45:12+00:00",
  "text": "Hello from Amsterdam!",
  "author": {
    "id": "987654321",
    "username": "anna_amsterdam",
    "first_name": "Анна",
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
    { "type": "photo", "id": 987654 }
  ]
}
```

## 🔺 Основные модули

- `adapter.py` — TelegramClient + events.NewMessage handler
- `mapper.py` — преобразование `telethon.Message` → Nekhebet payload
- `run.py` — основной цикл: подключение к БД/LMDB, подпись, сохранение
- `telegram/run.py` — точка входа (CLI-скрипт)

## 🔺 Инварианты

1. Адаптер **не хранит** состояние (кроме сессии Telethon)
2. Payload **детерминирован** и **JSON-сериализуем**
3. Нет загрузки медиа-файлов — только метаданные (Charon Vessel обрабатывает скачивание)
4. Подпись и сохранение происходят **после** создания конверта
5. При сбое подписи/сохранения событие **не теряется** — логируются ошибки

## 🔺 Лицензия

Proprietary (закрытая)

## 🔺 Краткое резюме

**Nekhebet Ingest** — это лёгкий, расширяемый слой приёма событий из внешних источников, который превращает сырые сообщения (Telegram как пример) в канонические неподписанные конверты Nekhebet и передаёт их на подпись и хранение.

Если сообщение попало в Telegram-чат → оно **очень скоро** станет математически доказуемо подлинным событием в Nekhebet.
