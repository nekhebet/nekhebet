# Nekhebet Core
**Криптографическое ядро верифицируемых событий (Zero-Trust)**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![msgspec](https://img.shields.io/badge/serialization-msgspec-orange)](https://jcristharif.com/msgspec/)
[![Ed25519](https://img.shields.io/badge/signature-Ed25519-9cf)](https://ed25519.cr.yp.to/)
[![cryptography](https://img.shields.io/badge/cryptography-42.0.0+-blue)](https://cryptography.io/)

Nekhebet Core — минималистичное криптографическое ядро для создания, подписи и строгой верификации событий в недоверенной среде.

Компонент реализует zero-trust модель: **никакие данные не считаются подлинными, пока это не доказано криптографически**.

Если событие прошло верификацию — оно подлинное.
Если нет — оно отвергается.
Без исключений.


## Задача, которую решает Core

* Приём событий из **недоверенных источников**
* Криптографическое доказательство:

  * подлинности
  * целостности
  * уникальности
* Защита от replay-атак
* Детерминированная верификация, пригодная для аудита и комплаенса

Core **не занимается**:

* хранением,
* транспортом,
* бизнес-логикой,
* визуализацией.

Это сознательное архитектурное ограничение.


## Ключевые гарантии

* **Ed25519** — единственный допустимый алгоритм подписи
* Подпись считается **строго над каноническим JSON** (RFC 8785, JCS)
* Zero-trust верификация: ничего не доверяется этапу создания
* Защита от replay-атак по тройке `(key_id, nonce, issued_at)`
* Append-only семантика на уровне протокола
* Жёсткие лимиты против DoS:

  * max payload: 1 MiB
  * ограниченная глубина структур
  * запрет зарезервированных полей
* Все ошибки верификации **детерминированы и категоризированы**


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

### Важный принцип

> Core **не знает**, откуда пришло событие
> 
> Core **не доверяет** создателю события
> 
> Core **доказывает**, подлинное оно или нет


## Формат события (упрощённо)

* `header`

  * `event_id`
  * `event_type`
  * `source`
  * `issued_at`
  * `key_id`
  * `nonce`
* `payload`
* `signature`

Любое отклонение от спецификации делает событие **недействительным**.

## Replay-защита

Replay-атака предотвращается проверкой уникальности тройки:

```
(key_id, nonce, issued_at)
```

Core предоставляет reference-реализацию (`InMemoryReplayGuard`).

Для production-использования предполагается внешнее хранилище
(Redis / PostgreSQL / KV-store).


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

replay_guard = InMemoryReplayGuard()

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

`verify_envelope` всегда возвращает `VerificationResult`:

* `valid: bool`
* `reason: str`
* `category: VerificationErrorCategory | None`

Это позволяет:

* логировать отказ,
* проводить аудит,
* анализировать атаки.


## Ограничения и допущения

* Канонизация соответствует RFC 8785 (JCS)

  * при использовании других языков требуется **строгое соответствие стандарту**
* Replay-guard должен обеспечивать согласованность на уровне системы
* Core не решает проблему доверия к ключам (key management — вне области)


## Когда стоит использовать Nekhebet Core

* аудит и комплаенс
* event sourcing в недоверенной среде
* ingestion данных из внешних источников
* forensic logging
* системы, где **доверие = угроза**


## Лицензия

MIT License


## Кратко

**Nekhebet Core — это криптографический фильтр реальности.**
Если событие прошло — оно подлинное.
Если нет — его не существует.

