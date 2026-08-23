#!/bin/sh
# ==============================================================================
#  NatBypass — Universal One-Line Installer for Keenetic, OpenWrt & Linux
# ==============================================================================

set -e

main() {
    REPO="jamixm4-crypto/natbypass"
    DEFAULT_TAG="v1.1.0"

    # Color Helpers
    print_purple() { printf "\033[0;35m%s\033[0m\n" "$1"; }
    print_cyan()   { printf "\033[0;36m%s\033[0m\n" "$1"; }
    print_green()  { printf "\033[0;32m%s\033[0m\n" "$1"; }
    print_yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
    print_red()    { printf "\033[0;31m%s\033[0m\n" "$1"; }
    print_bold()   { printf "\033[1;37m%s\033[0m\n" "$1"; }

    printf "\033[0;35m%s\n%s\n%s\n%s\n%s\n%s\033[0m\n" \
      "  _   _       _   ____                                " \
      " | \\ | | __ _| |_| __ ) _   _ _ __   __ _ ___ ___   " \
      " |  \\| |/ _  | __|  _ \\| | | | '_ \\ / _  / __/ __|  " \
      " | |\\  | (_| | |_| |_) | |_| | |_) | (_| \\__ \\__ \\  " \
      " |_| \\_|\\__,_|\\__|____/ \\__, | .__/ \\__,_|___/___/  " \
      "                        |___/|_|                    "

    echo "--------------------------------------------------------------"
    print_bold ">> Автоматическая установка NatBypass Mesh Network"
    echo "--------------------------------------------------------------"

    # 1. Detect Environment & Router Model
    RAW_ARCH=$(uname -m 2>/dev/null || echo "unknown")
    IS_KEENETIC=0
    IS_OPENWRT=0
    IS_SYSTEMD=0
    ROUTER_NAME=""

    if [ -f /opt/bin/opkg ] && [ -d /opt/etc ]; then
        IS_KEENETIC=1
        if [ -f /proc/device-tree/model ]; then
            ROUTER_NAME=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
        fi
        if [ -z "$ROUTER_NAME" ] && command -v ndmc >/dev/null 2>&1; then
            ROUTER_NAME=$(ndmc -c "show version" 2>/dev/null | grep -i 'model:' | awk -F': ' '{print $2}' | head -n1)
        fi
        if [ -z "$ROUTER_NAME" ]; then
            ROUTER_NAME="Keenetic Router (Entware)"
        fi
    elif [ -f /etc/openwrt_release ] || [ -f /etc/openwrt_version ]; then
        IS_OPENWRT=1
        if [ -f /tmp/sysinfo/model ]; then
            ROUTER_NAME=$(cat /tmp/sysinfo/model 2>/dev/null)
        else
            ROUTER_NAME="OpenWrt Router"
        fi
    elif command -v systemctl >/dev/null 2>&1; then
        IS_SYSTEMD=1
        ROUTER_NAME="Linux Server ($(uname -s 2>/dev/null))"
    else
        ROUTER_NAME="Generic Linux ($(uname -s 2>/dev/null))"
    fi

    # 2. Detect Architecture & Endianness
    case "${RAW_ARCH}" in
        x86_64|amd64)
            BIN_SUFFIX="linux-amd64"
            ARCH_DESC="x86_64 (PC / Server)"
            ;;
        aarch64|arm64)
            BIN_SUFFIX="linux-arm64"
            ARCH_DESC="ARM64 (Keenetic Titan/Hero/Giga/Ultra, RPi 4/5)"
            ;;
        mips)
            if echo -n I | hexdump -o 2>/dev/null | grep -q '0000000 0001'; then
                BIN_SUFFIX="router-mips"
                ARCH_DESC="MIPS Big-Endian"
            else
                BIN_SUFFIX="router-mipsle"
                ARCH_DESC="MIPS Little-Endian (Keenetic MT7621 / KN-1010)"
            fi
            ;;
        mips64)
            BIN_SUFFIX="router-mips"
            ARCH_DESC="MIPS64"
            ;;
        mipsel|mipsle)
            BIN_SUFFIX="router-mipsle"
            ARCH_DESC="MIPS Little-Endian (Keenetic / MT7621 / KN-1010 / Viva / Extra)"
            ;;
        armv7l|armv6l)
            BIN_SUFFIX="linux-arm64"
            ARCH_DESC="ARM 32/64"
            ;;
        *)
            print_yellow "[!] Нестандартная архитектура: ${RAW_ARCH}"
            BIN_SUFFIX="linux-amd64"
            ARCH_DESC="Generic (${RAW_ARCH})"
            ;;
    esac

    printf "✓ Устройство:       "; print_cyan "${ROUTER_NAME}"
    printf "✓ Архитектура ЦПУ:  "; print_cyan "${ARCH_DESC}"

    # 3. Setup Install Target Paths
    if [ "$IS_KEENETIC" -eq 1 ]; then
        TARGET_BIN="/opt/bin/natbypass"
        CONFIG_DIR="/opt/etc/natbypass"
        INIT_SCRIPT="/opt/etc/init.d/S99natbypass"
        SERVICE_TYPE="Keenetic Entware"
    elif [ "$IS_OPENWRT" -eq 1 ]; then
        TARGET_BIN="/usr/bin/natbypass"
        CONFIG_DIR="/etc/natbypass"
        INIT_SCRIPT="/etc/init.d/natbypass"
        SERVICE_TYPE="OpenWrt Procd"
    else
        TARGET_BIN="/usr/local/bin/natbypass"
        CONFIG_DIR="/etc/natbypass"
        SERVICE_TYPE="Linux systemd"
    fi

    printf "✓ Тип окружения:    "; print_cyan "${SERVICE_TYPE}"
    printf "✓ Путь установки:   "; print_cyan "${TARGET_BIN}"

    # 4. Create Directories
    mkdir -p "${CONFIG_DIR}" "$(dirname "${TARGET_BIN}")" /opt/etc/init.d /opt/var/log /var/run 2>/dev/null || true

    # Stop previous running instance if any
    if [ "$IS_KEENETIC" -eq 1 ] && [ -f "${INIT_SCRIPT}" ]; then
        "${INIT_SCRIPT}" stop >/dev/null 2>&1 || true
    elif [ "$IS_OPENWRT" -eq 1 ] && [ -f "${INIT_SCRIPT}" ]; then
        "${INIT_SCRIPT}" stop >/dev/null 2>&1 || true
    elif [ "$IS_SYSTEMD" -eq 1 ]; then
        systemctl stop natbypass >/dev/null 2>&1 || true
    fi
    killall natbypass 2>/dev/null || true

    # 5. Download Release Binary
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${DEFAULT_TAG}/natbypass-${DEFAULT_TAG}-${BIN_SUFFIX}"
    FALLBACK_URL="https://github.com/${REPO}/releases/latest/download/natbypass-${DEFAULT_TAG}-${BIN_SUFFIX}"

    echo ">> Загрузка бинарного файла ${BIN_SUFFIX}..."
    DOWNLOADED=0

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${DOWNLOAD_URL}" -o "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || \
        curl -fsSL "${FALLBACK_URL}" -o "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${DOWNLOAD_URL}" -O "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || \
        wget -q "${FALLBACK_URL}" -O "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || true
    fi

    if [ "$DOWNLOADED" -eq 0 ] || [ ! -s "${TARGET_BIN}" ]; then
        print_red "[!] Ошибка загрузки бинарного файла."
        print_yellow "URL: ${DOWNLOAD_URL}"
        exit 1
    fi

    chmod +x "${TARGET_BIN}"
    if [ "$IS_KEENETIC" -eq 1 ]; then
        mkdir -p /opt/usr/bin 2>/dev/null || true
        ln -sf /opt/bin/natbypass /opt/usr/bin/natbypass 2>/dev/null || true
    fi

    print_green "✓ Исполняемый файл успешно установлен и проверен."

    # 6. Generate Clean config.yaml if not exists
    CONFIG_FILE="${CONFIG_DIR}/config.yaml"
    if [ ! -f "${CONFIG_FILE}" ]; then
        echo ">> Создание конфигурации ${CONFIG_FILE}..."
        HOST_NAME="${ROUTER_NAME}"
        if [ -z "$HOST_NAME" ]; then
            HOST_NAME=$(uname -n 2>/dev/null || echo "Router")
        fi
        
        cat > "${CONFIG_FILE}" << EOF
app:
  name: "${HOST_NAME}"
  device_name: "${HOST_NAME}"
  version: "${DEFAULT_TAG}"
  log_level: "info"
  publish_interval: 10

web_ui:
  enabled: true
  port: 8080
  username: "admin"
  password: ""

network:
  upnp_enabled: true
  doh_enabled: true
  allow_exit_node: true
  advertised_subnets:
    - "192.168.1.0/24"
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun1.l.google.com:19302"
    - "stun.cloudflare.com:3478"

signaling:
  channels:
    - type: "mqtt"
      priority: 1
      enabled: true
      params:
        broker_url: "tcp://broker.emqx.io:1883"
        topic: "natbypass/mynet/peers"
    - type: "telegram"
      priority: 2
      enabled: false
      params:
        token: ""
        chat_id: ""

wireguard:
  enabled: true
  listen_port: 51820
  mtu: 1420
EOF
        print_green "✓ Конфигурация сохранена."
    fi

    # 7. Setup System Service and Autostart
    echo ">> Запуск службы NatBypass..."

    if [ "$IS_KEENETIC" -eq 1 ]; then
        cat > "${INIT_SCRIPT}" << 'EOF'
#!/bin/sh
ENABLED=yes
PROCS=natbypass
BIN=/opt/bin/natbypass
CONFIG=/opt/etc/natbypass/config.yaml
LOGFILE=/opt/var/log/natbypass.log
PIDFILE=/var/run/natbypass.pid
DESC="NatBypass Mesh Service"

start() {
    [ "$ENABLED" != "yes" ] && exit 0
    printf "Starting %s... " "$DESC"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "already running."
        return 0
    fi
    mkdir -p /opt/etc/natbypass /opt/var/log /var/run 2>/dev/null || true
    $BIN start --config "$CONFIG" > "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "done."
}

stop() {
    printf "Stopping %s... " "$DESC"
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    killall "$PROCS" 2>/dev/null || true
    echo "done."
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "$DESC is running (PID: $(cat "$PIDFILE"))"
    elif pidof "$PROCS" >/dev/null 2>&1; then
        echo "$DESC is running (PID: $(pidof "$PROCS"))"
    else
        echo "$DESC is stopped."
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 1
        start
        ;;
    status|check)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF
        chmod +x "${INIT_SCRIPT}"
        "${INIT_SCRIPT}" start
        print_green "✓ Служба Keenetic Entware запущена (/opt/etc/init.d/S99natbypass start)"

    elif [ "$IS_OPENWRT" -eq 1 ]; then
        cat > "${INIT_SCRIPT}" << 'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=95
STOP=10

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/natbypass start --config /etc/natbypass/config.yaml
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
        chmod +x "${INIT_SCRIPT}"
        /etc/init.d/natbypass enable
        /etc/init.d/natbypass start >/dev/null 2>&1 || true
        print_green "✓ Служба OpenWrt Procd запущена"

    elif [ "$IS_SYSTEMD" -eq 1 ]; then
        SERVICE_FILE="/etc/systemd/system/natbypass.service"
        cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=NatBypass P2P Mesh Network & AmneziaWG Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${TARGET_BIN} start --config ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable natbypass
        systemctl restart natbypass || systemctl start natbypass
        print_green "✓ Служба systemd запущена (systemctl enable --now natbypass)"
    else
        nohup "${TARGET_BIN}" start --config "${CONFIG_FILE}" >/dev/null 2>&1 &
        print_green "✓ Демон NatBypass запущен в фоновом режиме"
    fi

    # 8. IP Address Detection
    ROUTER_IP=""
    if [ -z "$ROUTER_IP" ]; then
        ROUTER_IP=$(ip addr show br0 2>/dev/null | grep -E 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -n1 || true)
    fi
    if [ -z "$ROUTER_IP" ]; then
        ROUTER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || true)
    fi
    if [ -z "$ROUTER_IP" ]; then
        ROUTER_IP=$(ip -4 addr show 2>/dev/null | grep -E 'inet 192\.168\.' | awk '{print $2}' | cut -d/ -f1 | head -n1 || true)
    fi
    if [ -z "$ROUTER_IP" ]; then
        ROUTER_IP=$(ip -4 addr show 2>/dev/null | grep -E 'inet 10\.' | awk '{print $2}' | cut -d/ -f1 | head -n1 || true)
    fi
    if [ -z "$ROUTER_IP" ]; then
        if [ "$IS_KEENETIC" -eq 1 ] || [ "$IS_OPENWRT" -eq 1 ]; then
            ROUTER_IP="192.168.1.1"
        else
            ROUTER_IP="127.0.0.1"
        fi
    fi

    echo ""
    echo "=============================================================="
    print_green "🎉 NatBypass успешно установлен и работает!"
    echo "=============================================================="
    printf " 🌐 Панель управления (Web UI): "; print_cyan "http://${ROUTER_IP}:8080"
    printf " 📁 Конфигурационный файл:     "; print_yellow "${CONFIG_FILE}"
    printf " 📋 Журнал работы (Логи):      "; print_cyan "/opt/var/log/natbypass.log"
    printf " ⚙️  Исполняемый файл:          %s\n" "${TARGET_BIN}"
    echo "=============================================================="
    print_bold " 💡 Подсказка: откройте в браузере http://${ROUTER_IP}:8080 для управления"
    echo ""
}

main "$@"