# Charon Vessel — Secure File Rotator

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![C++17](https://img.shields.io/badge/C++-17-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20FreeBSD-blue)
[![Single Binary](https://img.shields.io/badge/single-binary-lightgrey.svg)]()
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main&label=CI)](https://github.com/nekhebet/nekhebet/actions)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/nekhebet/nekhebet/ci-cd.yml?branch=main&label=CodeQL&logo=github)](https://github.com/nekhebet/nekhebet/actions/workflows/ci-cd.yml)


🇷🇺 [Русская версия README](#-русская-версия)  
🇬🇧 [English version below](#-english-version)

## 🔥 Кратко

**Charon Vessel** — высокопроизводительный и безопасный демон ротации файлов (single-file C++17).  
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
cd nekhebet/gadgets/charon-vessel
```
### Linux (рекомендуется с io_uring)
```bash
sudo apt install libcap-dev liburing-dev
g++ -std=c++17 -O3 -pthread -lcap -luring -o charon_vessel charon_vessel.cpp
```
### FreeBSD
```bash
clang++ -std=c++17 -O3 -march=native -flto -pthread -DNDEBUG -Wall -Wextra -Wpedantic -o charon_vessel charon_vessel.cpp
```
Установка:
```bash
sudo install -m 755 charon_vessel /usr/local/bin/
```

## ⚙️ Конфигурация (env-vars)
Минимально:
```bash
export FRESH_PATH="/var/charon/fresh"
export ARCHIVE_ROOT="/var/charon/archive"
export MAX_FRESH=100
```
Рекомендуемые:
```bash
export COPY_THREADS=8
export DISK_LIMIT_PCT=84
export RUN_AS_USER=charon
export ENABLE_AUDIT_LOG=1
export ENABLE_IO_URING=1 # только Linux
```
SIGHUP — перезагрузка конфигурации.

## 🛠️ Установка сервиса
### Linux (systemd)
Создайте /etc/systemd/system/charon_vessel.service:
```
[Unit]
Description=Защищённый демон ротации файлов Charon Vessel
After=network.target

[Service]
Type=simple
# === Основные пути ===
Environment="FRESH_PATH=/var/charon/fresh" # Директория для поступающих новых файлов
Environment="ARCHIVE_ROOT=/var/charon/archive" # Корень архива (файлы перемещаются в поддиректории YYYY/MM/DD/)
# === Основные параметры работы ===
Environment="MAX_FRESH=500" # Максимальное количество файлов в fresh-директории (при превышении — ротация)
Environment="COPY_THREADS=8" # Количество потоков для параллельного копирования при cross-device перемещении
Environment="DISK_LIMIT_PCT=84" # Порог заполнения диска в %, при превышении — агрессивная очистка архива
# === Безопасность ===
Environment="RUN_AS_USER=charon" # Пользователь для дропа привилегий (рекомендуется, пусто или "root" — работа от root)
Environment="ENABLE_AUDIT_LOG=1" # 1 — включить аудит операций в syslog, 0 — выключить
# Добавьте здесь другие переменные окружения при необходимости
# Примеры:
# Environment="ROTATION_SEC=7"
# Environment="MAX_AGE_DAYS=1825"
# Environment="VERBOSE_LOGGING=1"
# Environment="ENABLE_IO_URING=1" # только Linux
ExecStart=/usr/local/bin/charon_vessel start
ExecStop=/usr/local/bin/charon_vessel stop
Restart=on-failure
LimitNOFILE=1048576 # Увеличенный лимит открытых файлов

[Install]
WantedBy=multi-user.target
```
Затем:
```
systemctl daemon-reload
systemctl enable --now charon_vessel
```

### FreeBSD — install.sh (root)
```sh
#!/bin/sh
# Charon Vessel installer for FreeBSD
# Запуск от root
set -e # Прерывать выполнение при любой ошибке

# === Проверка запуска от root ===
if [ "$(id -u)" -ne 0 ]; then
    echo "ОШИБКА: Скрипт должен запускаться от root" >&2
    exit 1
fi

# === Конфигурируемые параметры ===
FRESH_PATH="/var/charon/fresh" # Директория, куда поступают новые файлы (сканируется на превышение лимита)
ARCHIVE_ROOT="/var/charon/archive" # Корневая директория архива. Файлы перемещаются в поддиректории вида YYYY/MM/DD/
PID_DIR="/var/run/charon" # Директория для pid-файла (создаётся автоматически)
MAX_FRESH="500" # Максимальное количество файлов в FRESH_PATH. При превышении старые файлы ротируются в архив
COPY_THREADS="8" # Количество потоков для параллельного копирования при cross-device перемещении
DISK_LIMIT_PCT="84" # Порог использования диска в процентах. При превышении включается агрессивная очистка архива
RUN_AS_USER="charon" # Пользователь, от имени которого будет работать демон.
                                                # - Если пусто или "root" → демон остаётся под root (без дропа привилегий)
                                                # - Если указано другое имя → создаётся пользователь и демон дропает привилегии
ENABLE_AUDIT_LOG="0" # 1 — включить аудит-лог операций, 0 — выключить

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
    echo "Проверка/создание пользователя $RUN_AS_USER..."
    if ! pw user show "$RUN_AS_USER" >/dev/null 2>&1; then
        echo "Создаём пользователя $RUN_AS_USER..."
        pw user add "$RUN_AS_USER" \
            -m \
            -s /usr/sbin/nologin \
            -d /nonexistent \
            -c "Charon Vessel file rotator service"
        echo "Пользователь $RUN_AS_USER успешно создан."
    else
        echo "Пользователь $RUN_AS_USER уже существует."
    fi
    echo "Установка владельца директорий на $RUN_AS_USER..."
    chown -R "$RUN_AS_USER:$RUN_AS_USER" "$FRESH_PATH" "$ARCHIVE_ROOT" "$PID_DIR"
else
    echo "RUN_AS_USER пустой или 'root' → демон будет работать от root (без дропа привилегий)"
    echo "Права на директории НЕ изменяются (остаются текущими)."
    echo "Убедитесь, что у root есть доступ к $FRESH_PATH и $ARCHIVE_ROOT"
fi

# Установка прав доступа (независимо от владельца)
echo "Установка прав доступа..."
chmod 750 "$FRESH_PATH" "$ARCHIVE_ROOT"
chmod 755 "$PID_DIR"

# === Копирование бинарного файла ===
BIN_DEST="/usr/local/bin/charon_vessel"
echo "Копирование бинарника в $BIN_DEST..."
if [ ! -f "./charon_vessel" ]; then
    echo "ОШИБКА: Файл charon_vessel не найден в текущей директории!" >&2
    exit 1
fi
cp -p "./charon_vessel" "$BIN_DEST" || {
    echo "ОШИБКА: Не удалось скопировать бинарник в $BIN_DEST" >&2
    exit 1
}
chmod 755 "$BIN_DEST"
echo "Бинарник установлен: $BIN_DEST"

# === Установка rc.d скрипта ===
RC_SCRIPT="/usr/local/etc/rc.d/charon_vessel"
echo "Установка rc.d скрипта в $RC_SCRIPT..."
cat > "$RC_SCRIPT" << EOF
#!/bin/sh
# PROVIDE: charon_vessel
# REQUIRE: LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="charon_vessel"
rcvar="charon_vessel_enable"
command="/usr/local/bin/charon_vessel"
command_args="start"
pidfile="${PID_DIR}/charon.pid"

# Переменные окружения по умолчанию
: \${charon_vessel_enable:="NO"}
: \${charon_vessel_env:="FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG"}

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
add_to_rc_conf 'charon_vessel_enable="YES"'
add_to_rc_conf "charon_vessel_env=\"FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG\""

# === Финальное сообщение ===
echo ""
echo "=================================================================="
echo "Установка Charon Vessel завершена успешно!"
echo "=================================================================="
echo "Для запуска службы:"
echo " service charon_vessel start"
echo ""
echo "Для проверки статуса:"
echo " service charon_vessel status"
echo ""
echo "Для остановки:"
echo " service charon_vessel stop"
echo ""
echo "Служба будет автоматически запускаться при загрузке системы."
echo "Логи доступны через syslog (daemon facility)."
echo ""
echo "Текущая конфигурация (стандартные пути):"
echo " FRESH_PATH = $FRESH_PATH"
echo " ARCHIVE_ROOT = $ARCHIVE_ROOT"
echo " RUN_AS_USER = $RUN_AS_USER (рекомендуемый безопасный режим)"
echo "Полный список параметров конфигурации — в исходном коде charon_vessel.cpp (структура Config)."
echo "=================================================================="
```
Сделайте исполняемым и запустите:
```sh
chmod +x install.sh
sudo ./install.sh
```

## 🏗️ Архитектура
### Основные модули:
- **Charon Vessel**: Ядро системы, конфигурация, оркестрация
- **Charon**: Перемещение файлов, кросс-устройственное копирование
- **Anubis**: Очистка устаревших файлов, управление дисковым пространством

### Ключевые компоненты:
- `unique_fd`: RAII-обертка для файловых дескрипторов
- `PidFileLock`: Гарантия единственного экземпляра
- `MemfdTempFile`: Безопасные временные файлы в памяти
- `CharonWorkerPool`: Пул потоков для копирования
- `SecurityAudit`: Система аудита операций

## 📊 Мониторинг
`charon_vessel status` — метрики.
```
rotated_total 12345 # Всего ротировано файлов
cross_device_moves 567 # Кросс-устройственных перемещений
cleanup_files 890 # Удалено устаревших файлов
errors 0 # Ошибок операций
active_copies 2 # Текущих параллельных копий
copy_bytes_total 45GB # Всего скопировано байт
security_errors 0 # Обнаруженных угроз безопасности
```
Полный список всех 30+ метрик — в функции charon_get_metrics в коде.
Аудит: в syslog ([AUDIT] префикс когда ENABLE_AUDIT_LOG=1).

Лицензия: MIT.  
Contributions welcome!

---
## 🇬🇧 English version

**Charon Vessel** is a high-performance secure file rotation daemon (single-file C++17 project).  
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
cd nekhebet/gadgets/charon-vessel
```
### Linux (io_uring recommended)
```bash
sudo apt install libcap-dev liburing-dev
g++ -std=c++17 -O3 -pthread -lcap -luring -o charon_vessel charon_vessel.cpp
```
### FreeBSD
```bash
clang++ -std=c++17 -O3 -march=native -flto -pthread -DNDEBUG -Wall -Wextra -Wpedantic -o charon_vessel charon_vessel.cpp
```
Install:
```bash
sudo install -m 755 charon_vessel /usr/local/bin/
```

## ⚙️ Configuration (env-vars)
Minimal:
```bash
export FRESH_PATH="/var/charon/fresh"
export ARCHIVE_ROOT="/var/charon/archive"
export MAX_FRESH=100
```
Recommended:
```bash
export COPY_THREADS=8
export DISK_LIMIT_PCT=84
export RUN_AS_USER=charon
export ENABLE_AUDIT_LOG=1
export ENABLE_IO_URING=1 # Linux only
```
SIGHUP reloads configuration.

## 🛠️ Service installation
### Linux (systemd)
Create `/etc/systemd/system/charon_vessel.service`.
```
[Unit]
Description=Charon Vessel Secure File Rotator
After=network.target

[Service]
Type=simple
# === Main paths ===
Environment="FRESH_PATH=/var/charon/fresh" # Directory for incoming new files
Environment="ARCHIVE_ROOT=/var/charon/archive" # Archive root (files moved to YYYY/MM/DD/ subdirectories)
# === Core operation parameters ===
Environment="MAX_FRESH=500" # Maximum number of files in fresh directory (rotation triggered when exceeded)
Environment="COPY_THREADS=8" # Number of threads for parallel copying during cross-device moves
Environment="DISK_LIMIT_PCT=84" # Disk usage threshold in %, aggressive archive cleanup starts when exceeded
# === Security ===
Environment="RUN_AS_USER=charon" # User for privilege dropping (recommended; empty or "root" runs as root)
Environment="ENABLE_AUDIT_LOG=1" # 1 — enable operation audit logging to syslog, 0 — disable
# Add other environment variables here if needed
# Examples:
# Environment="ROTATION_SEC=7"
# Environment="MAX_AGE_DAYS=1825"
# Environment="VERBOSE_LOGGING=1"
# Environment="ENABLE_IO_URING=1" # Linux only
ExecStart=/usr/local/bin/charon_vessel start
ExecStop=/usr/local/bin/charon_vessel stop
Restart=on-failure
LimitNOFILE=1048576 # Increased open file limit

[Install]
WantedBy=multi-user.target
```
Then:
```bash
systemctl daemon-reload
systemctl enable --now charon_vessel
```

### FreeBSD — install.sh (root)
Use the provided `install.sh` script.
```sh
#!/bin/sh
# Charon Vessel installer for FreeBSD
# Run as root
set -e # Exit on any error

# === Check for root privileges ===
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

# === Configurable parameters ===
FRESH_PATH="/var/charon/fresh" # Directory for incoming new files (scanned for limit exceeded)
ARCHIVE_ROOT="/var/charon/archive" # Archive root directory. Files are moved to YYYY/MM/DD/ subdirectories
PID_DIR="/var/run/charon" # Directory for the pid file (created automatically)
MAX_FRESH="500" # Maximum number of files in FRESH_PATH. Older files are rotated when exceeded
COPY_THREADS="8" # Number of threads for parallel copying on cross-device moves
DISK_LIMIT_PCT="84" # Disk usage percentage threshold. Aggressive archive cleanup starts when exceeded
RUN_AS_USER="charon" # User under which the daemon will run.
                                                # - Empty or "root" → daemon stays as root (no privilege drop)
                                                # - Any other name → user is created and daemon drops privileges
ENABLE_AUDIT_LOG="0" # 1 — enable audit logging of operations, 0 — disable

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
    echo "Checking/creating user $RUN_AS_USER..."
    if ! pw user show "$RUN_AS_USER" >/dev/null 2>&1; then
        echo "Creating user $RUN_AS_USER..."
        pw user add "$RUN_AS_USER" \
            -m \
            -s /usr/sbin/nologin \
            -d /nonexistent \
            -c "Charon Vessel file rotator service"
        echo "User $RUN_AS_USER created successfully."
    else
        echo "User $RUN_AS_USER already exists."
    fi
    echo "Setting directory ownership to $RUN_AS_USER..."
    chown -R "$RUN_AS_USER:$RUN_AS_USER" "$FRESH_PATH" "$ARCHIVE_ROOT" "$PID_DIR"
else
    echo "RUN_AS_USER is empty or 'root' → daemon will run as root (no privilege drop)"
    echo "Directory ownership is NOT changed (remains current)."
    echo "Ensure root has access to $FRESH_PATH and $ARCHIVE_ROOT"
fi

# Set permissions (regardless of owner)
echo "Setting permissions..."
chmod 750 "$FRESH_PATH" "$ARCHIVE_ROOT"
chmod 755 "$PID_DIR"

# === Copy the binary ===
BIN_DEST="/usr/local/bin/charon_vessel"
echo "Copying binary to $BIN_DEST..."
if [ ! -f "./charon_vessel" ]; then
    echo "ERROR: charon_vessel binary not found in current directory!" >&2
    exit 1
fi
cp -p "./charon_vessel" "$BIN_DEST" || {
    echo "ERROR: Failed to copy binary to $BIN_DEST" >&2
    exit 1
}
chmod 755 "$BIN_DEST"
echo "Binary installed: $BIN_DEST"

# === Install rc.d script ===
RC_SCRIPT="/usr/local/etc/rc.d/charon_vessel"
echo "Installing rc.d script to $RC_SCRIPT..."
cat > "$RC_SCRIPT" << EOF
#!/bin/sh
# PROVIDE: charon_vessel
# REQUIRE: LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="charon_vessel"
rcvar="charon_vessel_enable"
command="/usr/local/bin/charon_vessel"
command_args="start"
pidfile="${PID_DIR}/charon.pid"

# Default environment variables
: \${charon_vessel_enable:="NO"}
: \${charon_vessel_env:="FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG"}

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
add_to_rc_conf 'charon_vessel_enable="YES"'
add_to_rc_conf "charon_vessel_env=\"FRESH_PATH=$FRESH_PATH ARCHIVE_ROOT=$ARCHIVE_ROOT MAX_FRESH=$MAX_FRESH COPY_THREADS=$COPY_THREADS DISK_LIMIT_PCT=$DISK_LIMIT_PCT RUN_AS_USER=$RUN_AS_USER ENABLE_AUDIT_LOG=$ENABLE_AUDIT_LOG\""

# === Final message ===
echo ""
echo "=================================================================="
echo "Charon Vessel installation completed successfully!"
echo "=================================================================="
echo "To start the service:"
echo " service charon_vessel start"
echo ""
echo "To check status:"
echo " service charon_vessel status"
echo ""
echo "To stop:"
echo " service charon_vessel stop"
echo ""
echo "The service will start automatically on boot."
echo "Logs are available via syslog (daemon facility)."
echo ""
echo "Current configuration (default paths):"
echo " FRESH_PATH = $FRESH_PATH"
echo " ARCHIVE_ROOT = $ARCHIVE_ROOT"
echo " RUN_AS_USER = $RUN_AS_USER (recommended secure mode)"
echo "Full list of configuration parameters — in charon_vessel.cpp source (Config struct)."
echo "=================================================================="
```
Then:
```sh
chmod +x install.sh
sudo ./install.sh
```

## 🏗️ Architecture
### Main modules:
- **Charon Vessel: Core system, configuration, orchestration**
- **Charon: File movement, cross-device copying**
- **Anubis: Cleanup of old files, space management**

### Key components:
- `unique_fd`: RAII wrapper for file descriptors
- `PidFileLock`: Single instance guarantee
- `MemfdTempFile`: Secure in-memory temp files
- `CharonWorkerPool`: Thread pool for copying
- `SecurityAudit`: Operation audit system

## 📊 Monitoring
`charon_vessel status` — shows status and metrics. Example key metrics:
```
rotated_total 12345 # Total rotated files
cross_device_moves 567 # Cross-device moves
cleanup_files 890 # Cleaned up old files
errors 0 # Operation errors
active_copies 2 # Current parallel copies
copy_bytes_total 45GB # Total copied bytes
security_errors 0 # Detected security threats
```
Full list of 30+ metrics — in `charon_get_metrics` function in code.
Audit: in syslog ([AUDIT] prefix when ENABLE_AUDIT_LOG=1).

License: MIT.  
Contributions welcome!

