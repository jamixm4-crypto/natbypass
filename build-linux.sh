#!/usr/bin/env bash
# ============================================================
#  NatBypass — интерактивный сборщик для Linux (Debian/Ubuntu)
#  Использование:
#    chmod +x build-linux.sh && ./build-linux.sh
#    ./build-linux.sh --unattended --tg-token "123:ABC" --tg-chat "-10012345" --target router
# ============================================================
set -euo pipefail

# ── Цвета ─────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;37m'
BOLD='\033[1m'; NC='\033[0m'

h()    { echo -e "${CYAN}${BOLD}$*${NC}"; }
step() { echo -e "${YELLOW}>> $*${NC}"; }
ok()   { echo -e "${GREEN}   OK: $*${NC}"; }
err()  { echo -e "${RED}   ОШИБКА: $*${NC}" >&2; }
info() { echo -e "${GRAY}   $*${NC}"; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="${PROJECT_ROOT}/dist"
MODULE="github.com/natbypass/natbypass"
CMD="./cmd/natbypass"

# ── Значения по умолчанию ─────────────────────────────────────
UNATTENDED=0
TARGET=""
TG_TOKEN=""
TG_CHAT_ID=""
MQTT_BROKER=""
MQTT_TOPIC=""
WEBHOOK_URL=""
DEVICE_ID=""
WEBUI_PORT="8080"
WEBUI_USER="admin"
WEBUI_PASS=""
LOG_LEVEL="info"

# ── Парсинг аргументов ─────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --unattended)     UNATTENDED=1 ;;
    --target)         TARGET="$2";       shift ;;
    --tg-token)       TG_TOKEN="$2";     shift ;;
    --tg-chat)        TG_CHAT_ID="$2";   shift ;;
    --mqtt-broker)    MQTT_BROKER="$2";  shift ;;
    --mqtt-topic)     MQTT_TOPIC="$2";   shift ;;
    --webhook-url)    WEBHOOK_URL="$2";  shift ;;
    --device-id)      DEVICE_ID="$2";    shift ;;
    --webui-port)     WEBUI_PORT="$2";   shift ;;
    --webui-user)     WEBUI_USER="$2";   shift ;;
    --webui-pass)     WEBUI_PASS="$2";   shift ;;
    --log-level)      LOG_LEVEL="$2";    shift ;;
    -h|--help)
      echo "Использование: $0 [OPTIONS]"
      echo ""
      echo "  --unattended            Неинтерактивный режим"
      echo "  --target all|router|linux|windows  Цель сборки"
      echo "  --tg-token TOKEN        Токен Telegram-бота"
      echo "  --tg-chat CHAT_ID       ID чата/канала Telegram"
      echo "  --mqtt-broker URL       URL MQTT-брокера"
      echo "  --mqtt-topic TOPIC      MQTT-топик"
      echo "  --webhook-url URL       URL HTTP Webhook"
      echo "  --device-id ID          Идентификатор устройства"
      echo "  --webui-port PORT       Порт Web UI (по умолч. 8080)"
      echo "  --webui-user USER       Пользователь Web UI"
      echo "  --webui-pass PASS       Пароль Web UI"
      echo "  --log-level LEVEL       debug|info|warn|error"
      echo ""
      echo "Примеры:"
      echo "  # Интерактивный режим"
      echo "  ./build-linux.sh"
      echo ""
      echo "  # Только роутеры, с Telegram"
      echo "  ./build-linux.sh --unattended --target router \\"
      echo "    --tg-token '123456:ABC' --tg-chat '-1001234567890'"
      echo ""
      echo "  # Полная сборка без GUI"
      echo "  ./build-linux.sh --unattended --target all"
      exit 0
      ;;
    *) err "Неизвестный аргумент: $1"; exit 1 ;;
  esac
  shift
done

# ── Функция диалога ───────────────────────────────────────────
prompt() {
  local label="$1" default="${2:-}" secret="${3:-}"
  if [[ "$default" != "" ]]; then
    printf "${WHITE}  ${label} [${default}]: ${NC}"
  else
    printf "${WHITE}  ${label}: ${NC}"
  fi
  if [[ "$secret" == "secret" ]]; then
    read -rs val; echo ""
  else
    read -r val
  fi
  if [[ "$val" == "" && "$default" != "" ]]; then
    echo "$default"
  else
    echo "$val"
  fi
}

prompt_choice() {
  local label="$1" default="$2"; shift 2
  echo ""
  echo -e "${WHITE}  ${label}${NC}"
  local i=1
  for opt in "$@"; do
    local mark="  "
    [[ "$opt" == "$default" ]] && mark="${GREEN}*${NC} "
    echo -e "  ${mark}${i}. ${opt}"
    (( i++ ))
  done
  printf "${WHITE}  Выбор [Enter = ${default}]: ${NC}"
  read -r choice
  if [[ "$choice" == "" ]]; then
    echo "$default"
  elif [[ "$choice" =~ ^[0-9]+$ ]]; then
    local opts=("$@")
    local idx=$(( choice - 1 ))
    echo "${opts[$idx]}"
  else
    echo "$default"
  fi
}

# ──────────────────────────────────────────────────────────────
clear
echo ""
h "╔═════════════════════════════════════════════════════╗"
h "║    NatBypass — Интерактивный сборщик для Linux      ║"
h "╚═════════════════════════════════════════════════════╝"
echo ""

# ── Шаг 1: Проверка/установка Go ─────────────────────────────
step "Проверка Go..."

GO_BIN=""

# Сначала ищем в soft/
if [[ -x "${PROJECT_ROOT}/soft/go/bin/go" ]]; then
  GO_BIN="${PROJECT_ROOT}/soft/go/bin/go"
  export GOROOT="${PROJECT_ROOT}/soft/go"
elif command -v go &>/dev/null; then
  GO_BIN="$(command -v go)"
else
  # Пробуем скачать Go автоматически
  step "Go не найден. Скачиваем Go 1.27.0..."
  GO_URL="https://go.dev/dl/go1.27.0.linux-amd64.tar.gz"
  GO_TAR="${PROJECT_ROOT}/soft/go1.27.0.linux-amd64.tar.gz"
  mkdir -p "${PROJECT_ROOT}/soft"
  
  if command -v curl &>/dev/null; then
    curl -fsSL --progress-bar "$GO_URL" -o "$GO_TAR"
  elif command -v wget &>/dev/null; then
    wget -q --show-progress "$GO_URL" -O "$GO_TAR"
  else
    err "Требуется curl или wget для загрузки Go"
    err "Установите вручную: sudo apt-get install -y golang-go"
    exit 1
  fi
  
  step "Распаковка Go..."
  tar -C "${PROJECT_ROOT}/soft" -xzf "$GO_TAR"
  GO_BIN="${PROJECT_ROOT}/soft/go/bin/go"
  export GOROOT="${PROJECT_ROOT}/soft/go"
  ok "Go установлен в soft/go/"
fi

export GOPATH="${PROJECT_ROOT}/soft/gopath"
export PATH="$(dirname $GO_BIN):${GOPATH}/bin:${PATH}"
mkdir -p "$GOPATH"

GO_VER=$("$GO_BIN" version 2>&1)
ok "$GO_VER"

# ── Шаг 2: Параметры ──────────────────────────────────────────
if [[ "$UNATTENDED" == "0" ]]; then
  echo ""
  h "━━━ Параметры конфигурации ━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  info "Параметры вшиваются в бинарник как умолчания."
  info "Можно переопределить через config.yaml или NATBYPASS_* env."
  echo ""

  echo -e "${CYAN}  [Telegram Bot API]${NC}"
  TG_TOKEN=$(prompt "Токен бота (@BotFather)" "$TG_TOKEN" "secret")
  TG_CHAT_ID=$(prompt "ID чата/канала (например -1001234567890)" "$TG_CHAT_ID")

  echo ""
  echo -e "${CYAN}  [MQTT]${NC}"
  MQTT_BROKER=$(prompt "URL брокера (Enter = пропустить)" "$MQTT_BROKER")
  if [[ "$MQTT_BROKER" != "" ]]; then
    [[ "$MQTT_TOPIC" == "" ]] && MQTT_TOPIC="natbypass/mynet/peers"
    MQTT_TOPIC=$(prompt "Топик" "$MQTT_TOPIC")
  fi

  echo ""
  echo -e "${CYAN}  [HTTP Webhook]${NC}"
  WEBHOOK_URL=$(prompt "URL webhook POST (Enter = пропустить)" "$WEBHOOK_URL")

  echo ""
  echo -e "${CYAN}  [Общие настройки]${NC}"
  DEVICE_ID=$(prompt "Device ID (Enter = авто)" "$DEVICE_ID")
  WEBUI_PORT=$(prompt "Порт Web UI" "$WEBUI_PORT")
  WEBUI_USER=$(prompt "Пользователь Web UI" "$WEBUI_USER")
  WEBUI_PASS=$(prompt "Пароль Web UI" "$WEBUI_PASS" "secret")
  LOG_LEVEL=$(prompt_choice "Уровень логирования" "info" "info" "debug" "warn" "error")
  LOG_LEVEL="${LOG_LEVEL%% *}"  # убираем лишнее

  echo ""
  echo -e "${CYAN}  [Целевые платформы]${NC}"
  if [[ "$TARGET" == "" ]]; then
    TARGET=$(prompt_choice "Что собирать?" "all" \
      "all    — все платформы" \
      "router — роутеры (mips + mipsle + arm64)" \
      "linux  — Linux amd64 + arm64" \
      "windows — только Windows")
    TARGET="${TARGET%% *}"
  fi
fi

# ── Шаг 3: Метаданные ─────────────────────────────────────────
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILDDATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo ""
h "━━━ Параметры сборки ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Версия:    ${VERSION} (${COMMIT})"
info "Дата:      ${BUILDDATE}"
info "Telegram:  $([ -n "$TG_TOKEN" ] && echo 'задан' || echo 'не задан')"
info "Chat ID:   $([ -n "$TG_CHAT_ID" ] && echo "$TG_CHAT_ID" || echo 'не задан')"
info "MQTT:      $([ -n "$MQTT_BROKER" ] && echo "$MQTT_BROKER" || echo 'не задан')"
info "Webhook:   $([ -n "$WEBHOOK_URL" ] && echo "$WEBHOOK_URL" || echo 'не задан')"
info "Web UI:    :${WEBUI_PORT}  user=${WEBUI_USER}"
info "Log:       ${LOG_LEVEL}"
info "Цель:      ${TARGET}"

if [[ "$UNATTENDED" == "0" ]]; then
  echo ""
  printf "${WHITE}  Начать сборку? [Y/n]: ${NC}"
  read -r confirm
  if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then
    echo "  Отменено."
    exit 0
  fi
fi

# ── Шаг 4: go mod tidy ────────────────────────────────────────
echo ""
step "go mod tidy (загрузка зависимостей)..."
cd "$PROJECT_ROOT"
"$GO_BIN" mod tidy
ok "Зависимости загружены"

# ── Шаг 5: ldflags ────────────────────────────────────────────
LDFLAGS="-s -w \
  -X ${MODULE}/cmd/natbypass.Version=${VERSION} \
  -X ${MODULE}/cmd/natbypass.Commit=${COMMIT} \
  -X ${MODULE}/cmd/natbypass.BuildDate=${BUILDDATE} \
  -X ${MODULE}/cmd/natbypass.DefaultTgToken=${TG_TOKEN} \
  -X ${MODULE}/cmd/natbypass.DefaultTgChatID=${TG_CHAT_ID} \
  -X ${MODULE}/cmd/natbypass.DefaultMQTTBroker=${MQTT_BROKER} \
  -X ${MODULE}/cmd/natbypass.DefaultMQTTTopic=${MQTT_TOPIC} \
  -X ${MODULE}/cmd/natbypass.DefaultWebhookURL=${WEBHOOK_URL} \
  -X ${MODULE}/cmd/natbypass.DefaultDeviceID=${DEVICE_ID} \
  -X ${MODULE}/cmd/natbypass.DefaultWebUIPort=${WEBUI_PORT} \
  -X ${MODULE}/cmd/natbypass.DefaultWebUIUser=${WEBUI_USER} \
  -X ${MODULE}/cmd/natbypass.DefaultWebUIPass=${WEBUI_PASS} \
  -X ${MODULE}/cmd/natbypass.DefaultLogLevel=${LOG_LEVEL}"

# ── Шаг 6: Функция сборки ─────────────────────────────────────
mkdir -p "$DIST"

build() {
  local goos="$1" goarch="$2" ext="${3:-}" extra="${4:-}"
  local name="natbypass-${goos}-${goarch}${ext}"
  local out="${DIST}/${name}"

  printf "   ${WHITE}%-30s${NC}" "${goos}/${goarch}..."

  local env_extra=""
  [[ "$extra" != "" ]] && env_extra="$extra "

  if env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" $env_extra \
      "$GO_BIN" build -trimpath -ldflags="$LDFLAGS" -o "$out" "$CMD" 2>/tmp/nb_build_err; then
    local sz
    sz=$(du -h "$out" | cut -f1)
    echo -e " ${GREEN}OK${NC} [${sz}]"
  else
    echo -e " ${RED}ОШИБКА${NC}"
    cat /tmp/nb_build_err >&2
    return 1
  fi
}

# ── Шаг 7: Сборка ─────────────────────────────────────────────
echo ""
h "━━━ Сборка: ${TARGET} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
BUILD_OK=1

case "$TARGET" in
  all)
    build windows amd64 ".exe"                     || BUILD_OK=0
    build linux   amd64                            || BUILD_OK=0
    build linux   arm64                            || BUILD_OK=0
    build linux   mips   "" "GOMIPS=softfloat"    || BUILD_OK=0
    build linux   mipsle "" "GOMIPS=softfloat"    || BUILD_OK=0
    ;;
  router)
    build linux arm64                              || BUILD_OK=0
    build linux mips   "" "GOMIPS=softfloat"      || BUILD_OK=0
    build linux mipsle "" "GOMIPS=softfloat"      || BUILD_OK=0
    ;;
  linux)
    build linux amd64                             || BUILD_OK=0
    build linux arm64                             || BUILD_OK=0
    ;;
  windows)
    build windows amd64 ".exe"                    || BUILD_OK=0
    ;;
  *)
    err "Неизвестная цель: $TARGET (доступно: all, router, linux, windows)"
    exit 1
    ;;
esac

# ── Шаг 8: Генерация config.yaml ─────────────────────────────
CONFIG_OUT="${DIST}/config.yaml"
cat > "$CONFIG_OUT" <<ENDCONFIG
# NatBypass — конфигурация (сгенерирована сборщиком ${BUILDDATE})
app:
  log_level: "${LOG_LEVEL}"
  publish_interval: 60
  device_id: "${DEVICE_ID}"

web_ui:
  enabled: true
  port: ${WEBUI_PORT}
  username: "${WEBUI_USER}"
  password: "${WEBUI_PASS}"

network:
  upnp_enabled: true
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun1.l.google.com:19302"
    - "stun.cloudflare.com:3478"
  ip_apis:
    - "https://api.ipify.org"
    - "https://ifconfig.me/ip"
    - "https://icanhazip.com"

signaling:
  channels:
ENDCONFIG

if [[ "$TG_TOKEN" != "" ]]; then
cat >> "$CONFIG_OUT" <<ENDCONFIG
    - type: "telegram"
      priority: 1
      enabled: true
      params:
        token: "${TG_TOKEN}"
        chat_id: "${TG_CHAT_ID}"
ENDCONFIG
fi

if [[ "$MQTT_BROKER" != "" ]]; then
cat >> "$CONFIG_OUT" <<ENDCONFIG
    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "${MQTT_BROKER}"
        topic: "${MQTT_TOPIC}"
ENDCONFIG
fi

if [[ "$WEBHOOK_URL" != "" ]]; then
cat >> "$CONFIG_OUT" <<ENDCONFIG
    - type: "webhook"
      priority: 3
      enabled: true
      params:
        post_url: "${WEBHOOK_URL}"
        poll_url: "${WEBHOOK_URL}"
ENDCONFIG
fi

cat >> "$CONFIG_OUT" <<ENDCONFIG

wireguard:
  enabled: false
  interface: "wg0"
  listen_port: 51820
ENDCONFIG

info "Конфиг: ${CONFIG_OUT}"

# ── Итог ──────────────────────────────────────────────────────
echo ""
if [[ "$BUILD_OK" == "1" ]]; then
  h "╔═════════════════════════════════════════════════════╗"
  h "║   ✓ Сборка завершена успешно!                       ║"
  h "╚═════════════════════════════════════════════════════╝"
  echo ""
  echo -e "${WHITE}  Бинарники в ${DIST}/:${NC}"
  ls -lh "${DIST}/" | grep -v "^total" | awk '{print "    "$NF"\t"$5}'
  echo ""
  # Проверка MIPS
  for f in "${DIST}/natbypass-linux-mips" "${DIST}/natbypass-linux-mipsle"; do
    [[ -f "$f" ]] || continue
    sz_mb=$(( $(stat -c%s "$f" 2>/dev/null || stat -f%z "$f") / 1024 / 1024 ))
    if (( sz_mb > 10 )); then
      echo -e "  ${YELLOW}⚠ ПРЕДУПРЕЖДЕНИЕ: $(basename $f) = ${sz_mb}МБ (цель для MIPS: <10МБ)${NC}"
    else
      echo -e "  ${GREEN}✓ $(basename $f) = ${sz_mb}МБ (OK для MIPS)${NC}"
    fi
  done
else
  h "╔═════════════════════════════════════════════════════╗"
  h "║   ✗ Сборка завершена с ОШИБКАМИ                     ║"
  h "╚═════════════════════════════════════════════════════╝"
  exit 1
fi
