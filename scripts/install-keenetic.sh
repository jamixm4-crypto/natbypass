#!/bin/bash
# ============================================================
# NatBypass — скрипт установки на Keenetic (через Entware)
# Запустите на роутере: bash install-keenetic.sh
# ============================================================

set -euo pipefail

ARCH=$(uname -m)
APP_DIR="/opt/etc/natbypass"
BIN_DIR="/opt/usr/sbin"
INIT_DIR="/opt/etc/init.d"
VERSION="latest"
GITHUB_REPO="natbypass/natbypass"

echo "============================================================"
echo " NatBypass — установка на Keenetic"
echo " Архитектура: ${ARCH}"
echo "============================================================"

# Определяем архитектуру
case "${ARCH}" in
  aarch64|arm64)
    BINARY="natbypass-linux-arm64"
    ;;
  mips)
    BINARY="natbypass-linux-mips"
    ;;
  mipsel|mipsle)
    BINARY="natbypass-linux-mipsle"
    ;;
  *)
    echo "ОШИБКА: Неизвестная архитектура: ${ARCH}"
    echo "Поддерживаются: aarch64, mips, mipsel"
    exit 1
    ;;
esac

echo ">> Используется бинарник: ${BINARY}"

# Проверяем наличие Entware
if [[ ! -f /opt/bin/opkg ]]; then
  echo "ОШИБКА: Entware не установлен!"
  echo "Установите Entware через системный раздел Keenetic:"
  echo "  Система > Дополнения > Entware"
  exit 1
fi

# Создаём директории
echo ">> Создание директорий..."
mkdir -p "${APP_DIR}" "${BIN_DIR}" "${INIT_DIR}"

# Скачиваем бинарник
echo ">> Загрузка ${BINARY}..."
if command -v curl &>/dev/null; then
  curl -fsSL "https://github.com/${GITHUB_REPO}/releases/${VERSION}/download/${BINARY}" \
    -o "${BIN_DIR}/natbypass"
elif command -v wget &>/dev/null; then
  wget -q "https://github.com/${GITHUB_REPO}/releases/${VERSION}/download/${BINARY}" \
    -O "${BIN_DIR}/natbypass"
else
  echo "ОШИБКА: Требуется curl или wget"
  exit 1
fi

chmod +x "${BIN_DIR}/natbypass"
echo ">> Бинарник установлен: ${BIN_DIR}/natbypass"

# Копируем конфиг если его нет
if [[ ! -f "${APP_DIR}/config.yaml" ]]; then
  echo ">> Создание конфига по умолчанию..."
  "${BIN_DIR}/natbypass" --config "${APP_DIR}/config.yaml" 2>/dev/null || true
  
  # Если команда не создала конфиг, создаём минимальный
  if [[ ! -f "${APP_DIR}/config.yaml" ]]; then
    cat > "${APP_DIR}/config.yaml" <<'ENDCONFIG'
app:
  log_level: "info"
  publish_interval: 60
web_ui:
  enabled: true
  port: 8080
  username: "admin"
  password: "changeme"
network:
  upnp_enabled: true
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun.cloudflare.com:3478"
signaling:
  channels:
    - type: "mqtt"
      priority: 1
      enabled: true
      params:
        broker_url: "tcp://mqtt.eclipseprojects.io:1883"
        topic: "natbypass/mynetwork/peers"
wireguard:
  enabled: false
ENDCONFIG
  fi
fi

echo ">> Конфиг: ${APP_DIR}/config.yaml"

# Генерируем ключи
echo ">> Генерация ключей..."
"${BIN_DIR}/natbypass" keygen 2>/dev/null | \
  grep -E "^(public|private)_key:" | \
  tee /tmp/natbypass-keys.txt || true

echo ">> ВАЖНО: Сохраните ключи из /tmp/natbypass-keys.txt!"

# Устанавливаем init-скрипт
echo ">> Установка init-скрипта..."
cat > "${INIT_DIR}/S99natbypass" <<'ENDINIT'
#!/bin/sh
ENABLED=yes
PROCS=natbypass
ARGS="start --config /opt/etc/natbypass/config.yaml"
PREARGS=""
DESC="NatBypass"
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
. /opt/etc/init.d/rc.func
ENDINIT
chmod +x "${INIT_DIR}/S99natbypass"

# Запускаем сервис
echo ">> Запуск NatBypass..."
"${INIT_DIR}/S99natbypass" start

echo ""
echo "============================================================"
echo " NatBypass успешно установлен!"
echo ""
echo " Web UI:  http://$(uname -n):8080"
echo " Логи:    logread -f | grep natbypass"
echo " Стоп:    ${INIT_DIR}/S99natbypass stop"
echo " Старт:   ${INIT_DIR}/S99natbypass start"
echo " Статус:  ${INIT_DIR}/S99natbypass check"
echo ""
echo " Конфиг: ${APP_DIR}/config.yaml"
echo " ОТРЕДАКТИРУЙТЕ конфиг и укажите токен Telegram или MQTT"
echo "============================================================"
