# Nekhebet Core
**Криптографическое ядро верифицируемых событий**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![msgspec](https://img.shields.io/badge/serialization-msgspec-orange)](https://jcristharif.com/msgspec/)
[![Ed25519](https://img.shields.io/badge/signature-Ed25519-9cf)](https://ed25519.cr.yp.to/)
[![cryptography](https://img.shields.io/badge/cryptography-42.0.0+-blue)](https://cryptography.io/)

Nekhebet Core — самостоятельное криптографическое ядро для создания, подписи и строгой верификации событий в zero-trust модели.

Компонент обеспечивает математически доказуемую подлинность, целостность и уникальность событий независимо от источника и среды выполнения.

## Ключевые гарантии

- Подпись исключительно Ed25519 над каноническим представлением по RFC 8785 (JCS)
- Zero-trust верификация: ничего не доверяется этапу создания
- Защита от replay-атак по тройке (key_id, nonce, issued_at)
- Строго append-only семантика на уровне протокола
- Жёсткие лимиты против DoS (1 MiB payload, ограниченная глубина, reserved fields)
- Детерминированная канонизация и категоризация всех ошибок верификации

## Архитектура

```
Payload + Header → canonicalize → SHA-256 → Ed25519 sign → SignedEnvelope
                                   ↓
                        verify_envelope (zero-trust)
                                   ↓
                        VerificationResult (valid / category)
```

- Канонизация: RFC 8785 JCS (json.dumps + Ryu, с предупреждением о cross-language)
- Replay guard: reference in-memory реализация (для production — внешнее хранилище)
- Конфигурация: кэшированная из env с безопасными дефолтами

## Установка

```bash
pip install nekhebet-core
```

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

# 1. Подготовка ключей
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
ctx = DefaultSigningContext(private_key=priv, public_key=pub, key_id="test-key-01")
guard = InMemoryReplayGuard()

# 2. Создание и подпись
unsigned = create_envelope(
    event_type="omen.observed",
    payload={"temperature": 23.7, "location": "Amsterdam"},
    source="sensor-42",
    key_id="test-key-01",
)

signed = sign_envelope(unsigned, ctx)

# 3. Верификация
result = verify_envelope(signed, replay_guard=guard, strict=True)
print(result.valid)      # True
print(result.reason)     # "Envelope verified successfully"
```

## Лицензия

MIT License

## Краткое резюме

Nekhebet Core — минималистичное и строгое криптографическое ядро, гарантирующее математически доказуемую подлинность событий.

Если верификация прошла успешно — событие подлинное. Точка.
