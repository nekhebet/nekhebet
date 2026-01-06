#!/bin/sh
# Charon Vessel installer for FreeBSD
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
# Full list of supported parameters is in the Config struct in charon_vessel.cpp.
# Only the most commonly changed ones are listed here.

FRESH_PATH="/var/charon/fresh"                          # Directory for incoming new files (scanned for limit exceeded)
ARCHIVE_ROOT="/var/charon/archive"                      # Archive root directory. Files are moved to YYYY/MM/DD/ subdirectories
PID_DIR="/var/run/charon"                               # Directory for the pid file (created automatically)
MAX_FRESH="500"                                         # Maximum number of files in FRESH_PATH. Older files are rotated when exceeded
COPY_THREADS="8"                                        # Number of threads for parallel copying on cross-device moves
DISK_LIMIT_PCT="84"                                     # Disk usage percentage threshold. Aggressive archive cleanup starts when exceeded
RUN_AS_USER="charon"                                    # User under which the daemon will run.
                                                        #   - Empty or "root" → daemon stays as root (no privilege drop)
                                                        #   - Any other name → user is created and daemon drops privileges
ENABLE_AUDIT_LOG="0"                                    # 1 — enable audit logging of operations, 0 — disable

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
echo "    service charon_vessel start"
echo ""
echo "To check status:"
echo "    service charon_vessel status"
echo ""
echo "To stop:"
echo "    service charon_vessel stop"
echo ""
echo "The service will start automatically on boot."
echo "Logs are available via syslog (daemon facility)."
echo ""
echo "Current configuration (default paths):"
echo "    FRESH_PATH = $FRESH_PATH"
echo "    ARCHIVE_ROOT = $ARCHIVE_ROOT"
echo "    RUN_AS_USER = $RUN_AS_USER (recommended secure mode)"
echo "Full list of configuration parameters — in charon_vessel.cpp source (Config struct)."
echo "=================================================================="
