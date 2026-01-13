# Charon Vessel
**Secure Atomic File Rotation Daemon**

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![C++17](https://img.shields.io/badge/C++-17-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20FreeBSD-blue)
![Single Binary](https://img.shields.io/badge/single-binary-lightgrey.svg)
![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)

## 🔺 Обзор

**Charon Vessel** — лёгкий, высоконадёжный демон ротации файлов для Linux и FreeBSD.

Он выполняет **атомарную ротацию** файлов из директории `FRESH` в `ARCHIVE` при достижении заданных лимитов (количество файлов или суммарный размер), гарантируя:

- отсутствие race conditions
- защиту от symlink-, hardlink- и TOCTOU-атак
- строгие проверки безопасности на каждом шаге
- полную предсказуемость поведения даже при сбоях и перезапусках

Всё реализовано в **одном самодостаточном бинарном файле** без внешних зависимостей и runtime-библиотек.

## 🔺 Назначение

> Надёжно перемещать большие объёмы файлов из рабочей директории в архив  
> в условиях потенциально враждебной или многопоточной среды.

Charon Vessel идеален для:

- логов (nginx, app, audit)
- временных выгрузок (S3 multipart uploads, backups)
- промежуточных данных в ETL-пайплайнах
- любых сценариев, где важна атомарность и защита от атак на файловую систему

## 🔺 Ключевой инвариант

> Файл существует **либо полностью во FRESH, либо полностью в ARCHIVE** —  
> промежуточных состояний **не бывает никогда**.

## 🔺 Архитектурная модель

```
Incoming files → FRESH/                  (watched directory)
                 ↓ (atomic rename when limit reached)
               ARCHIVE/YYYY-MM-DD_HH-MM-SS/   (timestamped subdir)
                 ↓ (parallel copy if cross-device)
               Final archived state
```

Каждый шаг использует только POSIX-примитивы (`rename()`, `link()`, `copy_file_range()` / `sendfile()`) с предварительной валидацией.

## 🔺 Установка и запуск

Сборка (одна команда):

```bash
# Требования: cmake >= 3.14, g++ или clang с C++17
git clone https://github.com/nekhebet/charon-vessel.git
cd charon-vessel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
sudo cp build/charon-vessel /usr/local/bin/
```

Запуск (пример):

```bash
# Минимальная конфигурация через переменные окружения
FRESH_DIR=/var/spool/fresh \
ARCHIVE_DIR=/var/archive \
MAX_FRESH_FILES=10000 \
MAX_FRESH_SIZE_GB=50 \
charon-vessel
```

Или как systemd-сервис:

```ini
[Unit]
Description=Charon Vessel - Secure File Rotation Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/charon-vessel
EnvironmentFile=/etc/charon-vessel.env
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 🔺 Основные переменные окружения

| Переменная              | Описание                                      | Default              |
|-------------------------|-----------------------------------------------|----------------------|
| `FRESH_DIR`             | Директория входящих файлов                    | — (обязательно)      |
| `ARCHIVE_DIR`           | Базовая директория архива                     | — (обязательно)      |
| `MAX_FRESH_FILES`       | Макс. кол-во файлов в FRESH                   | 10000                |
| `MAX_FRESH_SIZE_GB`     | Макс. размер в GiB                            | 50                   |
| `POLL_INTERVAL_SEC`     | Интервал проверки директории                  | 5                    |
| `MAX_PARALLEL_COPIES`   | Макс. параллельных копирований (cross-device) | 4                    |
| `LOG_LEVEL`             | quiet / info / debug                          | info                 |
| `CHECK_SYMLINKS`        | Включить защиту от symlink-атак (yes/no)      | yes                  |

## 🔺 Команды

```bash
charon-vessel status          # текущие метрики и состояние
charon-vessel version         # версия и сборка
charon-vessel help            # справка по переменным
```

## 🔺 Инварианты безопасности

1. Никаких операций без предварительной проверки пути
2. Запрет имён с `..` и абсолютных путей
3. Атомарность через `rename(2)` и `link(2)`
4. Защита от symlink / hardlink атак (O_NOFOLLOW, проверки)
5. Отказ при любом подозрительном состоянии
6. Нет временных файлов в целевых директориях
7. Перезапуск не нарушает консистентность

## 🔺 Ограничения

- Работает только на Linux и FreeBSD
- Требует прав на чтение/запись в обе директории
- Не поддерживает NFS с плохой семантикой rename
- Нет встроенной ротации по времени (только по лимитам)

## 🔺 Лицензия

MIT

## 🔺 Краткое резюме

**Charon Vessel** — это предельно минималистичный и максимально безопасный демон ротации файлов.

Он не пытается быть универсальным лог-ротационным инструментом.  
Он делает **одну вещь** — но делает её **безусловно корректно** даже в самых неприятных условиях.

Если файл попал в ARCHIVE — он туда попал **атомарно** и **навсегда**.  

