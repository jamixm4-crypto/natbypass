# NatBypass Universal Diagnostic Script for Linux / KeeneticOS / OpenWrt / Routers
# Usage: curl -sSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh

C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[1;34m'
C_CYAN='\033[1;36m'
C_BOLD='\033[1m'

printf "\n%b======================================================================%b\n" "$C_CYAN$C_BOLD" "$C_RESET"
printf "          🔍 NatBypass Universal Network & L3 Diagnostic Tool        \n"
printf "%b======================================================================%b\n\n" "$C_CYAN$C_BOLD" "$C_RESET"

REPORT_FILE="/tmp/natbypass_diag_$(date +%s).log"
echo "=== NatBypass Diagnostic Report ===" > "$REPORT_FILE"
echo "Timestamp: $(date -u)" >> "$REPORT_FILE"

log_section() {
    printf "\n%b▶ %s%b\n" "$C_BLUE$C_BOLD" "$1" "$C_RESET"
    printf "\n--- %s ---\n" "$1" >> "$REPORT_FILE"
}

log_ok() {
    printf "  %b[✓]%b %s\n" "$C_GREEN" "$C_RESET" "$1"
    printf "  [OK] %s\n" "$1" >> "$REPORT_FILE"
}

log_warn() {
    printf "  %b[!]%b %s\n" "$C_YELLOW" "$C_RESET" "$1"
    printf "  [WARN] %s\n" "$1" >> "$REPORT_FILE"
}

log_fail() {
    printf "  %b[✗]%b %s\n" "$C_RED" "$C_RESET" "$1"
    printf "  [FAIL] %s\n" "$1" >> "$REPORT_FILE"
}

log_info() {
    printf "  %b[i]%b %s\n" "$C_CYAN" "$C_RESET" "$1"
    printf "  [INFO] %s\n" "$1" >> "$REPORT_FILE"
}

# 1. System & Environment
log_section "1. СИСТЕМНОЕ ОКРУЖЕНИЕ И ПЛАТФОРМА"

OS_NAME="$(uname -s 2>/dev/null || echo 'Unknown')"
ARCH_NAME="$(uname -m 2>/dev/null || echo 'Unknown')"
HOST_NAME="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo 'Unknown')"
UPTIME_STR="$(uptime 2>/dev/null || echo 'Unknown')"

log_info "Хост: $HOST_NAME | ОС: $OS_NAME | Архитектура: $ARCH_NAME"
log_info "Аптайм: $UPTIME_STR"

if [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]; then
    log_ok "Права: root (Суперпользователь)"
else
    log_warn "Права: НЕ root! Рекомендуется запускать через sudo или под root."
fi

IS_KEENETIC=0
if grep -qi "keenetic" /proc/version 2>/dev/null || [ -x "/bin/ndmq" ] || [ -x "/usr/bin/ndmq" ] || [ -f "/etc/ndm/version" ]; then
    IS_KEENETIC=1
    log_info "Обнаружена платформа: KeeneticOS (NDM Framework)"
fi

if [ -e "/dev/net/tun" ]; then
    log_ok "Драйвер /dev/net/tun: ПРИСУТСТВУЕТ"
else
    log_fail "Драйвер /dev/net/tun: НЕ НАЙДЕН!"
fi

# 2. Процессы NatBypass
log_section "2. СОСТОЯНИЕ ПРОЦЕССА NATBYPASS"

NB_PIDS="$(pgrep -f 'natbypass' 2>/dev/null || ps | grep '[n]atbypass' | awk '{print $1}')"
if [ -n "$NB_PIDS" ]; then
    log_ok "Процесс NatBypass активен (PID: $NB_PIDS)"
    ps | grep '[n]atbypass' >> "$REPORT_FILE" 2>&1
else
    log_warn "Процесс NatBypass НЕ запущен!"
fi

# 3. Виртуальный интерфейс nb0
log_section "3. СЕТЕВОЙ ИНТЕРФЕЙС NB0 / TUN"

NB_IF=""
if ip link show dev nb0 >/dev/null 2>&1; then
    NB_IF="nb0"
elif ifconfig nb0 >/dev/null 2>&1; then
    NB_IF="nb0"
fi

if [ -n "$NB_IF" ]; then
    log_ok "Интерфейс $NB_IF найден в системе"
    IF_INFO="$(ip addr show dev "$NB_IF" 2>/dev/null || ifconfig "$NB_IF" 2>/dev/null)"
    echo "$IF_INFO" >> "$REPORT_FILE"
    
    IP_ADDR="$(echo "$IF_INFO" | grep -o 'inet [0-9.]*' | awk '{print $2}' || echo '')"
    MTU_VAL="$(echo "$IF_INFO" | grep -o 'mtu [0-9]*' | awk '{print $2}' || echo '')"
    
    if [ -n "$IP_ADDR" ]; then
        log_ok "Виртуальный IP: $IP_ADDR"
    else
        log_fail "IP адрес НЕ назначен на интерфейс $NB_IF!"
    fi
    
    if [ -n "$MTU_VAL" ]; then
        log_info "MTU интерфейса: $MTU_VAL"
    fi
    
    if echo "$IF_INFO" | grep -q "UP"; then
        log_ok "Статус интерфейса: UP (Активен)"
    else
        log_fail "Статус интерфейса: DOWN!"
    fi

    # Автоматическое восстановление интерфейса nb0 если он DOWN или без IP
    if ! echo "$IF_INFO" | grep -q "UP" || [ -z "$IP_ADDR" ]; then
        VIP_CANDIDATE="$(curl -s --max-time 1 http://127.0.0.1:8080/api/status 2>/dev/null | grep -o '"virtual_ip":"[^"]*"' | cut -d'"' -f4)"
        if [ -n "$VIP_CANDIDATE" ]; then
            log_warn "Авто-восстановление: подъем интерфейса $NB_IF и назначение $VIP_CANDIDATE..."
            ip link set dev "$NB_IF" mtu 1420 up 2>/dev/null
            ip addr flush dev "$NB_IF" 2>/dev/null
            ip addr add "$VIP_CANDIDATE/24" dev "$NB_IF" 2>/dev/null || ip addr add "$VIP_CANDIDATE/24" peer "$VIP_CANDIDATE" dev "$NB_IF" 2>/dev/null || ip addr add "$VIP_CANDIDATE/32" dev "$NB_IF" 2>/dev/null
            ip link set dev "$NB_IF" up 2>/dev/null
            SUBNET_PREF="$(echo "$VIP_CANDIDATE" | cut -d'.' -f1-3)"
            ip route replace "${SUBNET_PREF}.0/24" dev "$NB_IF" 2>/dev/null
            ip route replace "${SUBNET_PREF}.0/24" dev "$NB_IF" table main 2>/dev/null
            # Повторная проверка
            IF_INFO="$(ip addr show dev "$NB_IF" 2>/dev/null || ifconfig "$NB_IF" 2>/dev/null)"
            IP_ADDR="$(echo "$IF_INFO" | grep -o 'inet [0-9.]*' | awk '{print $2}' || echo '')"
            if echo "$IF_INFO" | grep -q "UP" && [ -n "$IP_ADDR" ]; then
                log_ok "Интерфейс $NB_IF успешно восстановлен: IP $IP_ADDR [UP]"
            fi
        fi
    fi
else
    log_fail "Виртуальный интерфейс nb0 НЕ существует!"
fi

# 4. Параметры ядра Linux (sysctl / procfs)
log_section "4. ПАРАМЕТРЫ СЕТЕВОГО СТЕКА ЯДРА LINUX"

check_sysctl() {
    FILE="/proc/sys/net/ipv4/$1"
    EXPECTED="$2"
    NAME="$3"
    if [ -f "$FILE" ]; then
        VAL="$(cat "$FILE" 2>/dev/null | tr -d ' \n')"
        if [ "$VAL" = "$EXPECTED" ]; then
            log_ok "$NAME ($1): $VAL [OK]"
        else
            log_warn "$NAME ($1): $VAL (Ожидалось $EXPECTED)"
        fi
    fi
}

check_sysctl "ip_forward" "1" "Маршрутизация IPv4 Forwarding"
check_sysctl "conf/all/rp_filter" "0" "Фильтрация обратного пути (all.rp_filter)"
check_sysctl "conf/default/rp_filter" "0" "Фильтрация обратного пути (default.rp_filter)"
if [ -n "$NB_IF" ]; then
    check_sysctl "conf/$NB_IF/rp_filter" "0" "Фильтрация обратного пути ($NB_IF.rp_filter)"
fi
check_sysctl "icmp_echo_ignore_all" "0" "Ответ ядра на ICMP Ping (icmp_echo_ignore_all)"

# 5. Маршрутизация
log_section "5. ТАБЛИЦЫ МАРШРУТИЗАЦИИ И ПРАВИЛА (IP ROUTE / IP RULE)"

log_info "Таблица маршрутов:"
if command -v ip >/dev/null 2>&1; then
    ip route show table main 2>/dev/null | grep -E 'nb0|10\.|100\.64' || ip route show 2>/dev/null | grep -E 'nb0|10\.|100\.64'
    ip route show table main >> "$REPORT_FILE" 2>&1
    log_info "Правила ip rule:"
    ip rule show 2>/dev/null | head -n 10
    ip rule show >> "$REPORT_FILE" 2>&1
fi

# 6. Брандмауэр iptables
log_section "6. БРАНДМАУЭР (IPTABLES / KEENETIC NDM)"

if command -v iptables >/dev/null 2>&1; then
    if iptables -C INPUT -i nb0 -j ACCEPT 2>/dev/null; then
        log_ok "Правило iptables INPUT для nb0: ACCEPT"
    else
        log_warn "Правило iptables INPUT для nb0 отсутствует"
    fi
    if [ "$IS_KEENETIC" -eq 1 ]; then
        if iptables -C _NDM_INPUT -i nb0 -j ACCEPT 2>/dev/null || iptables -L _NDM_INPUT -n -v 2>/dev/null | grep -q "nb0"; then
            log_ok "Цепочка KeeneticOS _NDM_INPUT для nb0: ACCEPT"
        else
            log_warn "Цепочка KeeneticOS _NDM_INPUT для nb0 отсутствует"
        fi
    fi
fi

# 7. Локальный API
log_section "7. ЛОКАЛЬНЫЙ API ДЕМОНА NATBYPASS (HTTP 127.0.0.1:8080)"

HTTP_GET() {
    URL="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -s -m 3 "$URL" 2>/dev/null || echo ""
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O - -T 3 "$URL" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

STATUS_JSON="$(HTTP_GET "http://127.0.0.1:8080/api/status")"
if [ -n "$STATUS_JSON" ]; then
    log_ok "Локальный API отвечает (HTTP 200)"
    echo "API Status: $STATUS_JSON" >> "$REPORT_FILE"
    PEERS_JSON="$(HTTP_GET "http://127.0.0.1:8080/api/peers")"
    if [ -n "$PEERS_JSON" ]; then
        log_section "8. СПИСОК ПОДКЛЮЧЕННЫХ ПИРОВ"
        echo "$PEERS_JSON" >> "$REPORT_FILE"
        echo "$PEERS_JSON"
    fi
else
    log_warn "Локальный API http://127.0.0.1:8080 недоступен"
fi

# 8. Сквозной ICMP Ping тест ко всем обнаруженным пирам
log_section "9. СКВОЗНОЙ ТЕСТ ICMP PING ДО ВСЕХ ОБНАРУЖЕННЫХ ПИРОВ"

test_ping() {
    TARGET_IP="$1"
    NAME="$2"
    CLEAN_IP="$(echo "$TARGET_IP" | awk -F'/' '{print $1}' | tr -d ' ')"
    if [ -z "$CLEAN_IP" ] || [ "$CLEAN_IP" = "0.0.0.0" ] || [ "$CLEAN_IP" = "<nil>" ]; then
        return
    fi
    if ping -c 2 -W 2 "$CLEAN_IP" >/dev/null 2>&1; then
        log_ok "Ping до $NAME ($CLEAN_IP): УСПЕШЕН!"
        echo "Ping $CLEAN_IP ($NAME): SUCCESS" >> "$REPORT_FILE"
    else
        log_fail "Ping до $NAME ($CLEAN_IP): НЕ ПРОХОДИТ (100% потерь)!"
        echo "Ping $CLEAN_IP ($NAME): FAIL" >> "$REPORT_FILE"
    fi
}

# 1. Пинг локального виртуального IP (проверка стека TUN)
if [ -n "$IP_ADDR" ]; then
    test_ping "$IP_ADDR" "Локальный узел (Self / nb0)"
fi

# 2. Динамический пинг всех пиров из API
PING_COUNT=0
if [ -n "$PEERS_JSON" ]; then
    # Извлекаем пары virtual_ip и device_name / device_id
    PEER_ENTRIES="$(echo "$PEERS_JSON" | grep -o '{"device_id":[^}]*' || echo '')"
    if [ -n "$PEER_ENTRIES" ]; then
        echo "$PEERS_JSON" | tr '}' '\n' | while read -r p_line; do
            VIP="$(echo "$p_line" | grep -o '"virtual_ip":"[^"]*' | cut -d'"' -f4)"
            DEV_NAME="$(echo "$p_line" | grep -o '"device_name":"[^"]*' | cut -d'"' -f4)"
            DEV_ID="$(echo "$p_line" | grep -o '"device_id":"[^"]*' | cut -d'"' -f4)"
            if [ -z "$DEV_NAME" ]; then
                DEV_NAME="$DEV_ID"
            fi
            if [ -n "$VIP" ] && [ "$VIP" != "$IP_ADDR" ]; then
                test_ping "$VIP" "$DEV_NAME"
            fi
        done
        PING_COUNT=1
    fi
fi

# Fallback: если пиров в API пока нет, проверяем стандартные тестовые узлы
if [ "$PING_COUNT" -eq 0 ]; then
    for fallback_ip in "10.123.111.1" "10.123.111.2" "10.123.111.110" "100.64.200.1"; do
        if [ "$fallback_ip" != "$IP_ADDR" ]; then
            test_ping "$fallback_ip" "Mesh узел (Fallback)"
        fi
    done
fi

printf "\n%b======================================================================%b\n" "$C_GREEN$C_BOLD" "$C_RESET"
printf "✓ Диагностический отчет сохранен в: %s\n" "$REPORT_FILE"
printf "%b======================================================================%b\n\n" "$C_GREEN$C_BOLD" "$C_RESET"
cat "$REPORT_FILE"