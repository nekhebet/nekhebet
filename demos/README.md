# Nekhebet — Secure File Rotator

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security Hardened](https://img.shields.io/badge/security-hardened-red.svg)
![C++17](https://img.shields.io/badge/C++-17-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20FreeBSD-green)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main&label=CI)](https://github.com/nekhebet/nekhebet/actions)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main&label=CodeQL&logo=github)](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml)
[![Single Binary](https://img.shields.io/badge/single-binary-lightgrey.svg)]()

🇷🇺 [Русская версия README](#-русская-версия)  
🇬🇧 [English version below](#-english-version)

## 🔥 Кратко

**Nekhebet** — высокопроизводительный и безопасный демон ротации файлов (single-file C++17).  
Предназначен для критически важных систем: ротация, управление файлами, кросс-устройственное перемещение с максимальной защитой от race conditions и атак.

### Основные особенности
- **Безопасность**: TOCTOU-защита, блокировка symlink/hardlink, path traversal checks, privilege dropping + capability strip (Linux), optional chroot, аудит операций.
- **Производительность**: zero-copy (io_uring → copy_file_range → fallback на Linux), адаптивные буферы, потокобезопасная очередь задач с низкой конкуренцией, параллельные потоки с throttling.
- **Надёжность**: контроль дискового пространства, graceful shutdown/reload (SIGHUP), детальные метрики.

## ⚠️ Важные замечания
1. **Требуются права root** для первоначального запуска (для chroot и setuid)
2. **Директории должны существовать** перед запуском
3. **Конфигурация через переменные окружения** обязательна
4. **Аудит-логи** требуют мониторинга
5. **FreeBSD** без xattr и io_uring
6. **Строгая валидация имён файлов**: наличие ".." в имени файла приводит к отклонению (намеренный подход для защиты от path traversal).

## 📦 Сборка

```bash
git clone https://github.com/nekhebet/nekhebet.git
cd nekhebet
```
### Linux (рекомендуется с io_uring)
```bash
sudo apt install libcap-dev liburing-dev
g++ -std=c++17 -O3 -pthread -lcap -luring -o nekhebet nekhebet.cpp
```

### FreeBSD
```bash
clang++ -std=c++17 -O3 -march=native -flto -pthread -DNDEBUG -Wall -Wextra -Wpedantic -o nekhebet nekhebet.cpp
```

Установка:
```bash
sudo install -m 755 nekhebet /usr/local/bin/
```

## ⚙️ Конфигурация (env-vars)

Минимально:
```bash
export FRESH_PATH="/var/nekhebet/fresh"
export ARCHIVE_ROOT="/var/nekhebet/archive"
export MAX_FRESH=100
```

Рекомендуемые:
```bash
export COPY_THREADS=8
export DISK_LIMIT_PCT=84
export RUN_AS_USER=nekhebet
export ENABLE_AUDIT_LOG=1
export ENABLE_IO_URING=1  # только Linux
```

SIGHUP — перезагрузка конфигурации.

## 🛠️ Установка сервиса

### Linux (systemd)

Создайте /etc/systemd/system/nekhebet.service:
```
[Unit]
Description=Защищённый демон ротации файлов Nekhebet
After=network.target

[Service]
Type=simple

# === Основные пути ===
Environment="FRESH_PATH=/var/nekhebet/fresh"          # Директория для поступающих новых файлов
Environment="ARCHIVE_ROOT=/var/nekhebet/archive"      # Корень архива (файлы перемещаются в поддиректории YYYY/MM/DD/)

# === Основные параметры работы ===
Environment="MAX_FRESH=500"                           # Максимальное количество файлов в fresh-директории (при превышении — ротация)
Environment="COPY_THREADS=8"                           # Количество потоков для параллельного копирования при cross-device перемещении
Environment="DISK_LIMIT_PCT=84"                        # Порог заполнения диска в %, при превышении — агрессивная очистка архива

# === Безопасность ===
Environment="RUN_AS_USER=nekhebet"                    # Пользователь для дропа привилегий (рекомендуется, пусто или "root" — работа от root)
Environment="ENABLE_AUDIT_LOG=1"                      # 1 — включить аудит операций в syslog, 0 — выключить

# Добавьте здесь другие переменные окружения при необходимости
# Примеры:
# Environment="ROTATION_SEC=7"
# Environment="MAX_AGE_DAYS=1825"
# Environment="VERBOSE_LOGGING=1"
# Environment="ENABLE_IO_URING=1"  # только Linux

ExecStart=/usr/local/bin/nekhebet start
ExecStop=/usr/local/bin/nekhebet stop
Restart=on-failure
LimitNOFILE=1048576                                    # Увеличенный лимит открытых файлов

[Install]
WantedBy=multi-user.target
```

Затем:
```
systemctl daemon-reload
systemctl enable --now nekhebet
```

### FreeBSD — install.sh (root)

```sh
#!/bin/sh
# Nekhebet installer for FreeBSD
# Запуск от root

set -e  # Прерывать выполнение при любой ошибке

# === Проверка запуска от root ===
if [ "$(id -u)" -ne 0 ]; then
    echo "ОШИБКА: Скрипт должен запускаться от root" >&2
    exit 1
fi

# === Конфигурируемые параметры ===
# Эти параметры передаются демону через переменные окружения и переопределяют значения по умолчанию в коде.
# Полный список поддерживаемых параметров смотрите в структуре Config в исходном коде (nekhebet.cpp).
# Здесь приведены только наиболее часто изменяемые.

FRESH_PATH="/var/nekhebet/fresh"                        # Директория, куда поступают новые файлы (сканируется на превышение лимита)
ARCHIVE_ROOT="/var/nekhebet/archive"                    # Корневая директория архива. Файлы перемещаются в поддиректории вида YYYY/MM/DD/
PID_DIR="/var/run/nekhebet"                             # Директория для pid-файла (создаётся автоматически)
MAX_FRESH="500"                                         # Максимальное количество файлов в FRESH_PATH. При превышении старые файлы ротируются в архив
COPY_THREADS="8"                                        # Количество потоков для параллельного копирования при cross-device перемещении
DISK_LIMIT_PCT="84"                                     # Порог использования диска в процентах. При превышении включается агрессивная очистка архива
RUN_AS_USER="nekhebet"                                  # Пользователь, от имени которого будет работать демон.
                                                        #   - Если пусто или "root" → демон остаётся под root (без дропа привилегий)
                                                        #   - Если указано другое имя → создаётся пользователь и демон дропает привилегии
ENABLE_AUDIT_LOG="0"                                    # 1 — включить аудит-лог операций, 0 — выключить

# Другие часто используемые параметры (можно добавить при необходимости):
# ROTATION_SEC="7"                        # Интервал сканирования fresh-директории в секундах (по умолчанию 7)
# CLEANUP_MIN="30"                        # Минимальный интервал между очистками архива в минутах (по умолчанию 30)
# MAX_AGE_DAYS="1825"                     # Максимальный возраст файлов в архиве в днях (по умолчанию ~5 лет)
# MAX_FILE_SIZE_GB="10"                   # Максимальный размер одного файла для обработки (по умолчанию 10 ГБ)
# ADAPTIVE_THROTTLE="1"                   # 1 — адаптивное управление потоками при нехватке места (рекомендуется)
# VERBOSE_LOGGING="0"                     # 1 — подробное логирование (удобно для отладки)

# === Создание необходимых директорий ===
echo "Создание рабочих директорий..."

for dir in "$FRESH_PATH" "$ARCHIVE_ROOT" "$PID_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "Создаём $dir"
        mkdir -p "$dir"
    else
        echo "Директория $dir уже существует."
    fi
done

# === Обработка пользователя и прав доступа ===
if [ -n "$RUN_AS_USER" ] && [ "$RUN_AS_USER" != "root" ]; then
    # Вариант с дропом привилегий: создаём отдельного непривилегированного пользователя
    echo "Проверка/создание пользователя $RUN_AS_USER..."
    if ! pw user show "$RUN_AS_USER" >/dev/null 2>&1; then
        echo "Создаём пользователя $RUN_AS_USER..."
        pw user add "$RUN_AS_USER" \
            -m \
            -s /usr/sbin/nologin \
            -d /nonexistent \
            -c "Nekhebet file rotator service"
        echo "Пользователь $RUN_AS_USER успешно создан."
    else
        echo "Пользователь $RUN_AS_USER уже существует."
    fi

    echo "Установка владельца директорий на $RUN_AS_USER..."
    chown -R "$RUN_AS_USER:$RUN_AS_USER" "$FRESH_PATH" "$ARCHIVE_ROOT" "$PID_DIR"
else
    # Без дропа привилегий: работаем от root, права не меняем
    echo "RUN_AS_USER пустой или 'root' → демон будет работать от root (без дропа привилегий)"
    echo "Права на директории НЕ изменяются (остаются текущими)."
    echo "Убедитесь, что у root есть доступ к $FRESH_PATH и $ARCHIVE_ROOT"
fi

# Установка прав доступа (независимо от владельца)
echo "Установка прав доступа..."
chmod 750 "$FRESH_PATH" "$ARCHIVE_ROOT"
chmod 755 "$PID_DIR"

# === Копирование бинарного файла ===
BIN_DEST="/usr/local/bin/nekhebet"

echo "Копирование бинарника в $BIN_DEST..."
if [ ! -f "./nekhebet" ]; then
    echo "ОШИБКА: Файл nekhebet не найден в текущей директории!" >&2
    exit 1
fi

cp -p "./nekhebet" "$BIN_DEST" || {
    echo "ОШИБКА: Не удалось скопировать бинарник в $BIN_DEST" >&2
    exit 1
}

chmod 755 "$BIN_DEST"
echo "Бинарник установлен: $BIN_DEST"

# === Установка rc.d скрипта ===
RC_SCRIPT="/usr/local/etc/rc.d/nekhebet"

echo "Установка rc.d скрипта в $RC_SCRIPT..."
cat > "$RC_SCRIPT" << EOF
#!/bin/sh
# PROVIDE: nekhebet
# REQUIRE: LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="nekhebet"
rcvar="nekhebet_enable"

command="/usr/local/bin/nekhebet"
command_args="start"
pidfile="${PID_DIR}/nekhebet.pid"

# Переменные окружения по умолчанию
: \${nekhebet_enable:="NO"}
: \${nekhebet_env:="FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG"}

load_rc_config \$name
run_rc_command "\$1"
EOF

chmod +x "$RC_SCRIPT"
echo "rc.d скрипт установлен и сделан исполняемым."

# === Настройка /etc/rc.conf ===
echo "Настройка автозапуска в /etc/rc.conf..."

add_to_rc_conf() {
    local line="$1"
    if ! grep -Fxq "$line" /etc/rc.conf 2>/dev/null; then
        echo "$line" >> /etc/rc.conf
        echo "Добавлено в /etc/rc.conf: $line"
    else
        echo "Уже присутствует в /etc/rc.conf: $line"
    fi
}

add_to_rc_conf 'nekhebet_enable="YES"'
add_to_rc_conf "nekhebet_env=\"FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG\""

# === Финальное сообщение ===
echo ""
echo "=================================================================="
echo "Установка Nekhebet завершена успешно!"
echo "=================================================================="
echo "Для запуска службы:"
echo "    service nekhebet start"
echo ""
echo "Для проверки статуса:"
echo "    service nekhebet status"
echo ""
echo "Для остановки:"
echo "    service nekhebet stop"
echo ""
echo "Служба будет автоматически запускаться при загрузке системы."
echo "Логи доступны через syslog (daemon facility)."
echo ""
echo "Текущая конфигурация (стандартные пути):"
echo "    FRESH_PATH = $FRESH_PATH"
echo "    ARCHIVE_ROOT = $ARCHIVE_ROOT"
echo "    RUN_AS_USER = $RUN_AS_USER (рекомендуемый безопасный режим)"
echo "Полный список параметров конфигурации — в исходном коде nekhebet.cpp (структура Config)."
echo "=================================================================="
```

Сделайте исполняемым и запустите:
```sh
chmod +x install.sh
sudo ./install.sh
```
## 🏗️ Архитектура

### Основные модули:
- **Nekhebet**: Ядро системы, конфигурация, оркестрация
- **Charon**: Перемещение файлов, кросс-устройственное копирование
- **Anubis**: Очистка устаревших файлов, управление дисковым пространством

### Ключевые компоненты:
- `unique_fd`: RAII-обертка для файловых дескрипторов
- `PidFileLock`: Гарантия единственного экземпляра
- `MemfdTempFile`: Безопасные временные файлы в памяти
- `CharonWorkerPool`: Пул потоков для копирования
- `SecurityAudit`: Система аудита операций

## 📊 Мониторинг

`nekhebet status` — метрики.  
```
textrotated_total 12345              # Всего ротировано файлов
cross_device_moves 567               # Кросс-устройственных перемещений
cleanup_files 890                    # Удалено устаревших файлов
errors 0                             # Ошибок операций
active_copies 2                      # Текущих параллельных копий
copy_bytes_total 45GB                # Всего скопировано байт
security_errors 0                    # Обнаруженных угроз безопасности
```
Полный список всех 30+ метрик — в функции nekhebet_get_metrics в коде.
Аудит: `/var/log/nekhebet-audit.log`.

Лицензия: MIT.  
Contributions welcome!

---

## 🇬🇧 English version

**Nekhebet** is a high-performance secure file rotation daemon (single-file C++17 project).  
Designed for critical systems: file rotation, management, cross-device moves with maximum protection against race conditions and attacks.

### Key features
- **Security**: TOCTOU protection, symlink/hardlink blocking, path traversal checks, privilege dropping + capability strip (Linux), optional chroot, operation audit.
- **Performance**: zero-copy (io_uring → copy_file_range → fallback on Linux), adaptive buffers, thread-safe task queue with low contention, parallel threads with throttling.
- **Reliability**: disk space control, graceful shutdown/reload (SIGHUP), detailed metrics.

## ⚠️ Important notes
1. **Root privileges required** for initial setup/launch (for chroot and setuid)
2. **Directories must exist** before launch
3. **Configuration via environment variables** only
4. **Audit logs** require monitoring
5. **FreeBSD**: no xattr or io_uring support
6. **Strict filename validation**: any occurrence of ".." in filenames is rejected (intentionally conservative to prevent path traversal).

## 📦 Build

```bash
git clone https://github.com/nekhebet/nekhebet.git
cd nekhebet
```
### Linux (io_uring recommended)
```bash
sudo apt install libcap-dev liburing-dev
g++ -std=c++17 -O3 -pthread -lcap -luring -o nekhebet nekhebet.cpp
```
### FreeBSD
```bash
clang++ -std=c++17 -O3 -march=native -flto -pthread -DNDEBUG -Wall -Wextra -Wpedantic -o nekhebet nekhebet.cpp
```
Install:
```bash
sudo install -m 755 nekhebet /usr/local/bin/
```

## ⚙️ Configuration (env-vars)
Minimal:
```bash
export FRESH_PATH="/var/nekhebet/fresh"
export ARCHIVE_ROOT="/var/nekhebet/archive"
export MAX_FRESH=100
```
Recommended:
```bash
export COPY_THREADS=8
export DISK_LIMIT_PCT=84
export RUN_AS_USER=nekhebet
export ENABLE_AUDIT_LOG=1
export ENABLE_IO_URING=1 # Linux only
```
SIGHUP reloads configuration.

## 🛠️ Service installation
### Linux (systemd)
Create `/etc/systemd/system/nekhebet.service`.  
```
[Unit]
Description=Nekhebet Secure File Rotator
After=network.target

[Service]
Type=simple

# === Main paths ===
Environment="FRESH_PATH=/var/nekhebet/fresh"          # Directory for incoming new files
Environment="ARCHIVE_ROOT=/var/nekhebet/archive"      # Archive root (files moved to YYYY/MM/DD/ subdirectories)

# === Core operation parameters ===
Environment="MAX_FRESH=500"                           # Maximum number of files in fresh directory (rotation triggered when exceeded)
Environment="COPY_THREADS=8"                           # Number of threads for parallel copying during cross-device moves
Environment="DISK_LIMIT_PCT=84"                        # Disk usage threshold in %, aggressive archive cleanup starts when exceeded

# === Security ===
Environment="RUN_AS_USER=nekhebet"                    # User for privilege dropping (recommended; empty or "root" runs as root)
Environment="ENABLE_AUDIT_LOG=1"                      # 1 — enable operation audit logging to syslog, 0 — disable

# Add other environment variables here if needed
# Examples:
# Environment="ROTATION_SEC=7"
# Environment="MAX_AGE_DAYS=1825"
# Environment="VERBOSE_LOGGING=1"
# Environment="ENABLE_IO_URING=1"  # Linux only

ExecStart=/usr/local/bin/nekhebet start
ExecStop=/usr/local/bin/nekhebet stop
Restart=on-failure
LimitNOFILE=1048576                                    # Increased open file limit

[Install]
WantedBy=multi-user.target
```
Then:
```bash
systemctl daemon-reload
systemctl enable --now nekhebet
```

### FreeBSD — install.sh (root)
Use the provided `install.sh` script.
```bash

#!/bin/sh
# Nekhebet installer for FreeBSD
# Run as root

set -e  # Exit on any error

# === Check for root privileges ===
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

# === Configurable parameters ===
# These parameters are passed to the daemon via environment variables
# and override the defaults defined in the code.
# Full list of supported parameters is in the Config struct in nekhebet.cpp.
# Only the most commonly changed ones are listed here.

FRESH_PATH="/var/nekhebet/fresh"                        # Directory for incoming new files (scanned for limit exceeded)
ARCHIVE_ROOT="/var/nekhebet/archive"                    # Archive root directory. Files are moved to YYYY/MM/DD/ subdirectories
PID_DIR="/var/run/nekhebet"                             # Directory for the pid file (created automatically)
MAX_FRESH="500"                                         # Maximum number of files in FRESH_PATH. Older files are rotated when exceeded
COPY_THREADS="8"                                        # Number of threads for parallel copying on cross-device moves
DISK_LIMIT_PCT="84"                                     # Disk usage percentage threshold. Aggressive archive cleanup starts when exceeded
RUN_AS_USER="nekhebet"                                  # User under which the daemon will run.
                                                        #   - Empty or "root" → daemon stays as root (no privilege drop)
                                                        #   - Any other name → user is created and daemon drops privileges
ENABLE_AUDIT_LOG="0"                                    # 1 — enable audit logging of operations, 0 — disable

# Other commonly used parameters (uncomment and adjust if needed):
# ROTATION_SEC="7"                        # Fresh directory scan interval in seconds (default 7)
# CLEANUP_MIN="30"                        # Minimum interval between archive cleanups in minutes (default 30)
# MAX_AGE_DAYS="1825"                     # Maximum file age in archive in days (default ~5 years)
# MAX_FILE_SIZE_GB="10"                   # Maximum file size for processing in GB (default 10 GB)
# ADAPTIVE_THROTTLE="1"                   # 1 — adaptive thread throttling when low on space (recommended)
# VERBOSE_LOGGING="0"                     # 1 — verbose logging (useful for debugging)

# === Create required directories ===
echo "Creating working directories..."

for dir in "$FRESH_PATH" "$ARCHIVE_ROOT" "$PID_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "Creating $dir"
        mkdir -p "$dir"
    else
        echo "Directory $dir already exists."
    fi
done

# === Handle user and permissions ===
if [ -n "$RUN_AS_USER" ] && [ "$RUN_AS_USER" != "root" ]; then
    # Privilege drop mode: create a dedicated unprivileged user
    echo "Checking/creating user $RUN_AS_USER..."
    if ! pw user show "$RUN_AS_USER" >/dev/null 2>&1; then
        echo "Creating user $RUN_AS_USER..."
        pw user add "$RUN_AS_USER" \
            -m \
            -s /usr/sbin/nologin \
            -d /nonexistent \
            -c "Nekhebet file rotator service"
        echo "User $RUN_AS_USER created successfully."
    else
        echo "User $RUN_AS_USER already exists."
    fi

    echo "Setting directory ownership to $RUN_AS_USER..."
    chown -R "$RUN_AS_USER:$RUN_AS_USER" "$FRESH_PATH" "$ARCHIVE_ROOT" "$PID_DIR"
else
    # No privilege drop: run as root, do not change ownership
    echo "RUN_AS_USER is empty or 'root' → daemon will run as root (no privilege drop)"
    echo "Directory ownership is NOT changed (remains current)."
    echo "Ensure root has access to $FRESH_PATH and $ARCHIVE_ROOT"
fi

# Set permissions (regardless of owner)
echo "Setting permissions..."
chmod 750 "$FRESH_PATH" "$ARCHIVE_ROOT"
chmod 755 "$PID_DIR"

# === Copy the binary ===
BIN_DEST="/usr/local/bin/nekhebet"

echo "Copying binary to $BIN_DEST..."
if [ ! -f "./nekhebet" ]; then
    echo "ERROR: nekhebet binary not found in current directory!" >&2
    exit 1
fi

cp -p "./nekhebet" "$BIN_DEST" || {
    echo "ERROR: Failed to copy binary to $BIN_DEST" >&2
    exit 1
}

chmod 755 "$BIN_DEST"
echo "Binary installed: $BIN_DEST"

# === Install rc.d script ===
RC_SCRIPT="/usr/local/etc/rc.d/nekhebet"

echo "Installing rc.d script to $RC_SCRIPT..."
cat > "$RC_SCRIPT" << EOF
#!/bin/sh
# PROVIDE: nekhebet
# REQUIRE: LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="nekhebet"
rcvar="nekhebet_enable"

command="/usr/local/bin/nekhebet"
command_args="start"
pidfile="${PID_DIR}/nekhebet.pid"

# Default environment variables
: \${nekhebet_enable:="NO"}
: \${nekhebet_env:="FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG"}

load_rc_config \$name
run_rc_command "\$1"
EOF

chmod +x "$RC_SCRIPT"
echo "rc.d script installed and made executable."

# === Configure /etc/rc.conf for autostart ===
echo "Configuring autostart in /etc/rc.conf..."

add_to_rc_conf() {
    local line="$1"
    if ! grep -Fxq "$line" /etc/rc.conf 2>/dev/null; then
        echo "$line" >> /etc/rc.conf
        echo "Added to /etc/rc.conf: $line"
    else
        echo "Already present in /etc/rc.conf: $line"
    fi
}

add_to_rc_conf 'nekhebet_enable="YES"'
add_to_rc_conf "nekhebet_env=\"FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG\""

# === Final message ===
echo ""
echo "=================================================================="
echo "Nekhebet installation completed successfully!"
echo "=================================================================="
echo "To start the service:"
echo "    service nekhebet start"
echo ""
echo "To check status:"
echo "    service nekhebet status"
echo ""
echo "To stop:"
echo "    service nekhebet stop"
echo ""
echo "The service will start automatically on boot."
echo "Logs are available via syslog (daemon facility)."
echo ""
echo "Current configuration (default paths):"
echo "    FRESH_PATH = $FRESH_PATH"
echo "    ARCHIVE_ROOT = $ARCHIVE_ROOT"
echo "    RUN_AS_USER = $RUN_AS_USER (recommended secure mode)"
echo "Full list of configuration parameters — in nekhebet.cpp source (Config struct)."
echo "=================================================================="
```
Then:
```sh
chmod +x install.sh
sudo ./install.sh
```
## 🏗️ Architecture
### Main modules:

- **Nekhebet: Core system, configuration, orchestration**
- **Charon: File movement, cross-device copying**
- **Anubis: Cleanup of old files, space management**

### Key components:

- `unique_fd`: RAII wrapper for file descriptors
- `PidFileLock`: Single instance guarantee
- `MemfdTempFile`: Secure in-memory temp files
- `CharonWorkerPool`: Thread pool for copying
- `SecurityAudit`: Operation audit system

## 📊 Monitoring
`nekhebet status` — shows status and metrics. Example key metrics:
```
rotated_total 12345                  # Total rotated files
cross_device_moves 567               # Cross-device moves
cleanup_files 890                    # Cleaned up old files
errors 0                             # Operation errors
active_copies 2                      # Current parallel copies
copy_bytes_total 45GB                # Total copied bytes
security_errors 0                    # Detected security threats
```
Full list of 30+ metrics — in `nekhebet_get_metrics` function in code.

Audit: in syslog ([AUDIT] prefix when ENABLE_AUDIT_LOG=1).

License: MIT.  
Contributions welcome! 


