# Nekhebet Core
**Cryptographically Verifiable Events — Signing & Verification Core**

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![msgspec](https://img.shields.io/badge/serialization-msgspec-orange)
![Ed25519](https://img.shields.io/badge/signature-Ed25519-9cf)

## 🔺 Обзор

**Nekhebet Core** — компактное криптографическое ядро для создания, подписи и строгой верификации событий в zero-trust модели.

Это самостоятельный компонент, который отвечает за:

- детерминированную канонизацию по RFC 8785 (JCS)
- подпись и проверку Ed25519
- защиту от replay-атак
- применение политик по типам событий
- жёсткую защиту от DoS и некорректных данных

Core задаёт **математические гарантии** всей системы Nekhebet: если событие прошло верификацию — оно подлинное, независимо от источника, времени и среды.

## 🔺 Ключевой инвариант

> Событие считается существующим только тогда,  
> когда его подпись и структура успешно прошли полную верификацию.

## 🔺 Основные гарантии

- Только **Ed25519** + **SHA-256**
- Канонизация строго по **RFC 8785** (JCS)
- Replay-защита по тройке `(key_id, nonce, issued_at)`
- Zero-trust: верификация не доверяет ничему из этапа создания
- Жёсткие лимиты: 1 MiB на канонизированный payload, ограниченная глубина, формат nonce и т.д.
- Категоризация всех ошибок для мониторинга и аудита
- Метрики signing/verification по типам событий

## 🔺 Установка

```bash
# Рекомендуемый способ
pip install nekhebet-core
```

```bash
# Репозиторий
pip install git+https://github.com/nekhebet/nekhebet-core.git@main
```

```bash
# Для локальной разработки и тестов (самый удобный вариант)
git clone https://github.com/nekhebet/nekhebet-core.git
cd nekhebet-core
pip install -e ".[dev]"          # с mypy, pytest, ruff и т.д.
```

Зависимости (автоматически):
- `msgspec>=0.18` — быстрая и строгая сериализация/валидация
- `cryptography>=42.0.0` — Ed25519

Требуется **Python 3.10+**.

Проверка установки:

```python
import nekhebet_core
print(nekhebet_core.__version__)                    # → 4.0.0 (или актуальная)
print(nekhebet_core.MAX_ABSOLUTE_PAYLOAD_SIZE)      # → 1048576
```

## 🔺 Формат события (SignedEnvelope)

```json
{
  "header": {
    "id":               "550e8400-e29b-41d4-a716-446655440000",
    "type":             "omen.observed",
    "version":          "4.0.0",
    "source":           "collector-01",
    "issued_at":        "2026-01-13T09:45:12.345Z",
    "expires_at":       "2026-01-13T10:45:12.345Z",   // опционально
    "nonce":            "a1b2c3d4e5f67890... (32–100 hex chars)",
    "key_id":           "ed25519:reg-001",
    "algorithm":        "ed25519",
    "canonicalization": "rfc8785",
    "payload_hash":     "64 символа sha256 lowercase",
    "context":          { ... },                      // опционально
    "extensions":       { ... }                       // опционально
  },
  "payload": {
    // любые JSON-значения — доменные данные
  },
  "signature": {
    "signature":  "base64(64 байта Ed25519 signature)",
    "public_key": "base64(32 байта Ed25519 public key)"
  }
}
```

## 🔺 Пример использования

```python
from nekhebet_core import (
    create_envelope,
    sign_envelope,
    verify_envelope,
    DefaultSigningContext,
    InMemoryReplayGuard,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Генерация ключа (в реальности — загрузка из безопасного хранилища)
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

signing_ctx = DefaultSigningContext(
    private_key=private_key,
    public_key=public_key,
    key_id="ed25519:reg-001"
)

replay_guard = InMemoryReplayGuard()

# 1. Создание события
unsigned = create_envelope(
    event_type="omen.observed",
    payload={"temperature": 23.7, "sensor_id": "ext-42"},
    source="collector-pi-07",
    key_id="ed25519:reg-001"
)

# 2. Подпись
signed = sign_envelope(unsigned, signing_ctx)

# 3. Верификация (самый критичный вызов)
result = verify_envelope(signed, replay_guard=replay_guard)

print(result.valid)          # True
print(result.reason)         # "Envelope verified successfully"
```

## 🔺 Важные модули

- `canonical.py` — **единственная** точка канонизации (JCS)
- `verification.py` — основной zero-trust конвейер проверки
- `envelope.py` — создание + валидация политик
- `signing.py` — подпись заголовка
- `replay_guard.py` — эталонная защита от повторов (in-memory)
- `types.py` — все структуры и константы (изменение → ломает подписи!)
- `registry.py` — политики типов событий

## 🔺 Инварианты, которые нельзя нарушать

1. Изменение структуры `EnvelopeHeader` → все подписи инвалидны
2. Изменение логики `canonicalize()` → все подписи инвалидны
3. Ослабление проверок в `verify_envelope()` → нарушение контракта
4. Игнорирование лимитов (`MAX_ABSOLUTE_PAYLOAD_SIZE`, глубины и т.д.)
5. Доверие любым данным вне `verify_envelope()`

## 🔺 Лицензия

MIT

## 🔺 Краткое резюме

**Nekhebet Core** — это минималистичное, строгое и самодостаточное криптографическое ядро, которое позволяет любой системе гарантировать:

> Каждое принятое событие имеет **математически доказуемую** подлинность, целостность и свежесть.

Если подпись прошла верификацию — событие настоящее.  
Точка.
