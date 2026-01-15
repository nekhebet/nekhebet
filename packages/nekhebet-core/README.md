# Nekhebet Core
**Криптографическое ядро верифицируемых событий (Zero-Trust)**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![msgspec](https://img.shields.io/badge/serialization-msgspec-orange)](https://jcristharif.com/msgspec/)
[![Ed25519](https://img.shields.io/badge/signature-Ed25519-9cf)](https://ed25519.cr.yp.to/)
[![cryptography](https://img.shields.io/badge/cryptography-43.0+-blue)](https://cryptography.io/)

Nekhebet Core — минималистичное криптографическое ядро для создания, подписи и строгой верификации событий в недоверенной среде.  
Реализует zero-trust модель: **никакие данные не считаются подлинными, пока это не доказано криптографически**.

Если событие прошло верификацию — оно подлинное.  
Если нет — оно отвергается.  
Без исключений.

## Задача, которую решает Core
- Приём событий из **недоверенных источников**
- Криптографическое доказательство подлинности, целостности и уникальности
- Защита от replay-атак
- Детерминированная верификация для аудита и комплаенса

Core **не занимается** хранением, транспортом, бизнес-логикой и визуализацией.  
Это сознательное архитектурное ограничение.

## Ключевые гарантии
- Единственный алгоритм подписи: **Ed25519**
- Подпись над **каноническим JSON** (RFC 8785 JCS) через msgspec
- Zero-trust верификация даже для локально созданных событий
- Replay-защита на уровне хранилища по уникальной паре `(key_id, nonce)`
- Append-only семантика на уровне протокола
- Защита от DoS: max payload 1 MiB, ограничение глубины, запрет зарезервированных полей
- Все ошибки верификации детерминированы и категоризированы

## Архитектура
```
Payload + Header
        ↓
Canonicalization (RFC 8785 JCS)
        ↓
SHA-256
        ↓
Ed25519 Sign
        ↓
SignedEnvelope
        ↓
verify_envelope (zero-trust)
        ↓
VerificationResult
```

> **Принцип**: Core не знает и не доверяет источнику события.  
> Он только доказывает — подлинное оно или нет.

## Формат события (упрощённо)
```json
{
  "header": {
    "event_id": "...",
    "event_type": "...",
    "source": "...",
    "issued_at": "...",
    "key_id": "...",
    "nonce": "..."
  },
  "payload": { ... },
  "signature": "..."
}
```
Любое отклонение от спецификации делает событие **недействительным**.

## Replay-защита
Replay-атака предотвращается проверкой уникальности пары `(key_id, nonce)`.  
Core предоставляет reference-реализацию `InMemoryReplayGuard`.  
Для production рекомендуется внешнее распределённое хранилище (Redis / PostgreSQL / KV-store).

## Установка
```bash
pip install nekhebet-core
```

Python 3.11+

## Быстрый старт
```python
from nekhebet_core import (
    create_envelope,
    sign_envelope,
    verify_envelope,
    DefaultSigningContext,
    InMemoryReplayGuard,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Генерация ключей
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

ctx = DefaultSigningContext(
    private_key=private_key,
    public_key=public_key,
    key_id="sensor-01",
)

replay_guard = InMemoryReplayGuard()  # Для production — внешний распределённый guard

# Создание события
unsigned = create_envelope(
    event_type="omen.observed",
    payload={"temperature": 23.7},
    source="sensor-42",
    key_id="sensor-01",
)

# Подпись
signed = sign_envelope(unsigned, ctx)

# Верификация (zero-trust)
result = verify_envelope(
    signed,
    replay_guard=replay_guard,
    strict=True,
)

assert result.valid is True
```

## Результат верификации
`VerificationResult` содержит:
- `valid: bool`
- `reason: str`
- `category: VerificationErrorCategory | None`

Позволяет логировать отказы, проводить аудит и анализировать атаки.

## Ограничения и допущения
- Канонизация строго по RFC 8785 (JCS). При использовании других языков требуются совместимые реализации.
- Replay-guard должен быть согласованным на уровне всей системы.
- Управление ключами вне области (рекомендуется HSM/KMS в production).

## Когда стоит использовать
- Аудит и комплаенс
- Event sourcing в недоверенной среде
- Ingest внешних данных
- Forensic logging
- Системы, где **доверие = угроза**

## Лицензия
MIT License

## Кратко
**Nekhebet Core — это криптографический фильтр реальности.**  
Если событие прошло — оно подлинное.  
Если нет — его не существует.
