# Charon Vessel — Secure File Rotation Infrastructure

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20FreeBSD-blue)
![C++17](https://img.shields.io/badge/C++-17-blue)
![Single Binary](https://img.shields.io/badge/single--binary-yes-lightgrey)
[![CI](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main\&label=CI)](https://github.com/nekhebet/nekhebet/actions)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main\&label=CodeQL)](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml)

**Charon Vessel** — инфраструктурный демон для **безопасной ротации и перемещения файлов**
в системах с жёсткими требованиями к целостности, изоляции и auditability.

Проектируется как **низкоуровневый security-primitive**, а не как универсальный файловый инструмент.

## Ключевая модель

Charon Vessel управляет жизненным циклом файлов между:

* **fresh** — активная зона приёма,
* **archive** — долговременное хранилище (иерархия по времени),
* **cleanup** — контролируемое удаление устаревших данных.

Все операции выполняются:

* атомарно,
* с защитой от race conditions,
* с минимальными привилегиями,
* с обязательной проверкой путей и имён файлов.


## Инварианты системы

### Security first

* защита от **TOCTOU**, **symlink / hardlink атак**,
* строгая проверка путей (path traversal defense),
* отказ от «умных» эвристик в пользу консервативных правил,
* privilege dropping + capability stripping (Linux),
* optional chroot,
* детальный аудит операций.

### Zero-trust I/O

* файловая система считается **недоверенной средой**,
* отсутствие предположений о корректности имён, путей и состояний,
* все внешние данные валидируются до выполнения операции.

### Deterministic behavior

* отсутствие скрытых side effects,
* предсказуемые правила ротации,
* воспроизводимые результаты при одинаковой конфигурации.

### Operational safety

* контроль заполнения диска,
* bounded resource usage,
* single-instance guarantee,
* graceful reload (SIGHUP).


## Архитектура

Charon Vessel — **один самодостаточный бинарник** (C++17).

### Основные компоненты

* **Core**

  * конфигурация,
  * сигналы,
  * оркестрация жизненного цикла.

* **Charon**

  * безопасное перемещение файлов,
  * zero-copy стратегии (io_uring → copy_file_range → fallback),
  * кросс-устройственные операции.

* **Anubis**

  * очистка устаревших файлов,
  * контроль дискового пространства,
  * аварийные режимы.

### Ключевые примитивы

* RAII для файловых дескрипторов,
* secure temporary files (memfd),
* thread-safe worker pools,
* явный security audit layer.


## Границы ответственности

Charon Vessel **НЕ**:

* файловый менеджер,
* backup-система,
* распределённое хранилище,
* планировщик задач.

Charon Vessel **ДА**:

* надёжный и проверяемый механизм файловых операций,
* строительный блок для storage / ingest / archival систем,
* компонент инфраструктуры, а не бизнес-логики.


## Типовые сценарии применения

* безопасная ротация логов,
* архивирование критичных данных,
* ingestion пайплайны,
* cold / warm storage,
* вспомогательный компонент для систем аудита и compliance.


## Статус проекта

* архитектура стабилизирована,
* интерфейсы минимальны и консервативны,
* внутренняя реализация может оптимизироваться без изменения модели.

Проект пригоден как:

* **production-grade utility**,
* **reference implementation security-first file rotation**,
* **open-source демонстрация инженерного подхода**.

## Лицензия

MIT


## Итог

**Charon Vessel** — это **инженерный фундамент** для безопасных файловых операций
в системах, где ошибка в работе с файловой системой недопустима.

Если **Nekhebet** отвечает за доверие к данным,
то **Charon Vessel** — за доверие к их физическому размещению.


