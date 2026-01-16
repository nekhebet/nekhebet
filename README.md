# Nekhebet
**Криптографически верифицируемый пайплайн событий в реальном времени**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](packages/)
[![Node.js](https://img.shields.io/badge/nodejs-20-blue)](demos/)
[![C++17](https://img.shields.io/badge/C++-17-blue)](gadgets/charon-vessel/)


<!-- CI/CD -->
[![CI](https://github.com/nekhebet/nekhebet/actions/workflows/ci.yml/badge.svg)](https://github.com/nekhebet/nekhebet/actions/workflows/ci.yml)
[![Charon Vessel CI/CD](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml)
[![CodeQL](https://github.com/nekhebet/nekhebet/actions/workflows/codeql.yml/badge.svg)](https://github.com/nekhebet/nekhebet/actions/workflows/codeql.yml)

Nekhebet — модульная zero-trust система для криптографически верифицируемого сбора, обработки, хранения и отображения событий из внешних источников в реальном времени.

Система обеспечивает криптографически проверяемую подлинность каждого принятого события в недоверенной среде: аутентичность, целостность и уникальность строго гарантированы.

## Компоненты

- **nekhebet-core** — криптографическое ядро протокола (подпись Ed25519, канонизация по RFC 8785 JCS, строгая верификация, защита от replay-атак)
- **nekhebet-store** — append-only хранилище (гибрид PostgreSQL + LMDB для метаданных и быстрого доступа к blob’ам)
- **nekhebet-ingest** — адаптеры приёма событий (Telegram как основной пример, расширяемо)
- **Charon Vessel** — демон атомарной ротации файлов (C++17, single binary, Linux/FreeBSD)
- **Omen Display** — веб-интерфейс реального времени для визуализации событий (Node.js + JavaScript)

## Ключевые гарантии

- Zero-trust верификация, независимая от источника и транспорта
- Математически доказуемая подлинность через Ed25519 над каноническим JCS-представлением
- Защита от replay-атак через уникальную пару (key_id, nonce)
- Строго append-only хранение — события никогда не модифицируются и не удаляются
- Атомарные операции с файлами с полной защитой от race-condition и symlink-атак

## Архитектура

```
Внешние источники
        ↓
Адаптеры приёма → UnsignedEnvelope
        ↓
Ядро (подпись + верификация)
        ↓
Хранилище (append-only)
        ↓
Потребители
   ├─ Omen Display (визуализация в реальном времени)
   ├─ Аналитика / Аудит
   └─ Charon Vessel (безопасная ротация файлов)
```

## Рабочая демонстрация

Инстанс Omen Display в реальном времени:  

<table class="mobile-table">
  <tr>
    <td colspan="2" class="mobile-main">
      <p> <img src="https://i.postimg.cc/qvRwVDvL/080808.png" alt="Nekhebet Omen Display" width="100%" /></p>
    </td>
  </tr>
  <tr>
    <td colspan="2" class="mobile-side">
    </td>
  </tr>
</table>

   ```
   http://0808.us.nekhebet.su:8080
   ```

(Инстанс получает события из тестового Telegram-канала и демонстрирует полный end-to-end пайплайн.)

## Быстрый старт

```bash
pip install nekhebet-core nekhebet-store nekhebet-ingest
```

Подробная настройка каждого компонента — в соответствующей директории пакета.

Полный локальный пример развертывания — в `examples/quick-start/` (docker-compose в разработке).

## Лицензия

MIT License

## Краткое резюме

Nekhebet предоставляет строгую криптографическую основу для систем, где требуется доказуемая подлинность событий: аудит, комплаенс, event-driven архитектуры, приём данных из недоверенных источников.
