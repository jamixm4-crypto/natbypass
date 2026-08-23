#!/bin/sh
# ==============================================================================
#  NatBypass — Universal One-Line Installer for Linux, Keenetic & OpenWrt
# ==============================================================================
#  Usage:
#    sh -c "$(curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh)"
#    or
#    wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
# ==============================================================================

set -e

REPO="jamixm4-crypto/natbypass"
DEFAULT_TAG="v1.1.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

printf "${PURPLE}"
cat << "EOF"
  _   _       _   ____                               
 | \ | | __ _| |_| __ ) _   _ _ __   __ _ ___ ___   
 |  \| |/ _` | __|  _ \| | | | '_ \ / _` / __/ __|  
 | |\  | (_| | |_| |_) | |_| | |_) | (_| \__ \__ \  
 |_| \_|\__,_|\__|____/ \__, | .__/ \__,_|___/___/  
                        |___/|_|                    
EOF
printf "${NC}\n"
echo ">> Автоматическая установка NatBypass для Linux и роутеров"
echo "--------------------------------------------------------------"

# 1. Detect Architecture & Endianness
RAW_ARCH=$(uname -m 2>/dev/null || echo "unknown")
IS_KEENETIC=0
IS_OPENWRT=0
IS_SYSTEMD=0

if [ -f /opt/bin/opkg ] && [ -d /opt/etc ]; then
    IS_KEENETIC=1
elif [ -f /etc/openwrt_release ] || [ -f /etc/openwrt_version ]; then
    IS_OPENWRT=1
elif command -v systemctl >/dev/null 2>&1; then
    IS_SYSTEMD=1
fi

case "${RAW_ARCH}" in
    x86_64|amd64)
        BIN_SUFFIX="linux-amd64"
        ARCH_DESC="x86_64 (PC / Server)"
        ;;
    aarch64|arm64)
        BIN_SUFFIX="linux-arm64"
        ARCH_DESC="ARM64 (Keenetic Titan/Hero, Raspberry Pi 4/5)"
        ;;
    mips)
        # Check endianness
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
        ARCH_DESC="MIPS Little-Endian (Keenetic / MT7621 / KN-1010 / Extra)"
        ;;
    armv7l|armv6l)
        BIN_SUFFIX="linux-arm64"
        ARCH_DESC="ARM 32/64"
        ;;
    *)
        echo "${RED}[!] Неизвестная архитектура: ${RAW_ARCH}${NC}"
        echo "Попытка использовать сборку linux-amd64..."
        BIN_SUFFIX="linux-amd64"
        ARCH_DESC="Generic (${RAW_ARCH})"
        ;;
esac

echo "✓ Архитектура устройства: ${CYAN}${ARCH_DESC}${NC}"

# 2. Select Paths depending on Environment
if [ "$IS_KEENETIC" -eq 1 ]; then
    TARGET_BIN="/opt/usr/bin/natbypass"
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

echo "✓ Окружение: ${CYAN}${SERVICE_TYPE}${NC}"
echo "✓ Путь установки: ${TARGET_BIN}"

# 3. Create Directories
mkdir -p "${CONFIG_DIR}" "$(dirname "${TARGET_BIN}")"

# 4. Download Binary
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${DEFAULT_TAG}/natbypass-${DEFAULT_TAG}-${BIN_SUFFIX}"
FALLBACK_URL="https://github.com/${REPO}/releases/latest/download/natbypass-${DEFAULT_TAG}-${BIN_SUFFIX}"

echo ">> Загрузка бинарного файла NatBypass..."
DOWNLOADED=0

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${DOWNLOAD_URL}" -o "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || \
    curl -fsSL "${FALLBACK_URL}" -o "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || true
elif command -v wget >/dev/null 2>&1; then
    wget -q "${DOWNLOAD_URL}" -O "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || \
    wget -q "${FALLBACK_URL}" -O "${TARGET_BIN}" 2>/dev/null && DOWNLOADED=1 || true
fi

if [ "$DOWNLOADED" -eq 0 ] || [ ! -s "${TARGET_BIN}" ]; then
    echo "${RED}[!] Ошибка загрузки бинарника с GitHub Releases.${NC}"
    echo "Проверьте URL: ${DOWNLOAD_URL}"
    exit 1
fi

chmod +x "${TARGET_BIN}"
echo "${GREEN}✓ Бинарный файл успешно загружен и установлен.${NC}"

# 5. Create Default config.yaml if not exists
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
if [ ! -f "${CONFIG_FILE}" ]; then
    echo ">> Генерация базового конфига ${CONFIG_FILE}..."
    HOST_NAME=$(uname -n 2>/dev/null || echo "Router-Node")
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
        topic: "natbypass/public/peers"
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
    echo "${GREEN}✓ Конфигурационный файл создан.${NC}"
fi

# 6. Service Installation & Autostart
echo ">> Настройка системной службы автозапуска..."

if [ "$IS_KEENETIC" -eq 1 ]; then
    # Keenetic Entware init script
    cat > "${INIT_SCRIPT}" << 'EOF'
#!/bin/sh
ENABLED=yes
PROCS=natbypass
ARGS="start --config /opt/etc/natbypass/config.yaml"
PREARGS=""
DESC="NatBypass P2P Mesh & AmneziaWG Service"
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
. /opt/etc/init.d/rc.func
EOF
    chmod +x "${INIT_SCRIPT}"
    "${INIT_SCRIPT}" restart >/dev/null 2>&1 || "${INIT_SCRIPT}" start >/dev/null 2>&1 || true
    echo "${GREEN}✓ Служба Entware настроена и запущена (${INIT_SCRIPT})${NC}"

elif [ "$IS_OPENWRT" -eq 1 ]; then
    # OpenWrt procd init script
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
    /etc/init.d/natbypass restart >/dev/null 2>&1 || /etc/init.d/natbypass start >/dev/null 2>&1 || true
    echo "${GREEN}✓ Служба OpenWrt Procd настроена и запущена${NC}"

elif [ "$IS_SYSTEMD" -eq 1 ]; then
    # Linux systemd service
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
    echo "${GREEN}✓ Служба systemd (natbypass.service) включена и запущена${NC}"
else
    # Background runner fallback
    killall natbypass 2>/dev/null || true
    nohup "${TARGET_BIN}" start --config "${CONFIG_FILE}" >/dev/null 2>&1 &
    echo "${GREEN}✓ NatBypass запущен в фоновом режиме${NC}"
fi

# 7. IP Address detection for Web UI banner
ROUTER_IP="127.0.0.1"
if command -v ip >/dev/null 2>&1; then
    ROUTER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "127.0.0.1")
elif command -v ifconfig >/dev/null 2>&1; then
    ROUTER_IP=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n1 || echo "127.0.0.1")
fi

echo ""
echo "=============================================================="
echo "${GREEN}🎉 Установка NatBypass успешно завершена!${NC}"
echo "=============================================================="
echo " 🌐 Панель управления (Web UI): ${CYAN}http://${ROUTER_IP}:8080${NC}"
echo " 📁 Конфигурационный файл:     ${YELLOW}${CONFIG_FILE}${NC}"
echo " ⚙️  Исполняемый файл:          ${TARGET_BIN}"
echo "=============================================================="
echo ""