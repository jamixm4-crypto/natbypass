#!/bin/sh
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

RAW_PIDS="$(pgrep -f 'natbypass' 2>/dev/null || ps | grep '[n]atbypass' | awk '{print $1}')"
REAL_PIDS=""
PID_COUNT=0
for p in $RAW_PIDS; do
    [ "$p" = "$$" ] && continue
    CMD="$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null || ps -p $p -o comm= 2>/dev/null || echo "")"
    if echo "$CMD" | grep -qiE 'diag\.sh|wget|curl|grep'; then
        continue
    fi
    if [ -d "/proc/$p" ] || kill -0 "$p" 2>/dev/null; then
        REAL_PIDS="$REAL_PIDS $p"
        PID_COUNT=$((PID_COUNT + 1))
    fi
done
REAL_PIDS="$(echo "$REAL_PIDS" | tr '\n' ' ' | xargs 2>/dev/null || echo "$REAL_PIDS")"

if [ "$PID_COUNT" -eq 1 ]; then
    log_ok "Процесс NatBypass активен (PID: $REAL_PIDS)"
    ps | grep '[n]atbypass' | grep -v 'grep' >> "$REPORT_FILE" 2>&1
elif [ "$PID_COUNT" -gt 1 ]; then
    log_fail "ВНИМАНИЕ: Запущено НЕСКОЛЬКО экземпляров NatBypass (PID: $REAL_PIDS)!"
    log_warn "Конфликт процессов приводит к сбоям MQTT и STUN. Завершите их: killall -9 natbypass"
    ps | grep '[n]atbypass' | grep -v 'grep' >> "$REPORT_FILE" 2>&1
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
    
    IP_ADDR="$(echo "$IF_INFO" | grep -o 'inet [0-9.]*' | awk '{print $2}' | head -n1 || echo '')"
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

# 4. Параметры ядра Linux (sysctl / procfs / conntrack / buffers)
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

# 4.1 Conntrack Saturation Check (Критично для роутеров Keenetic / OpenWrt)
if [ -f "/proc/sys/net/netfilter/nf_conntrack_count" ] && [ -f "/proc/sys/net/netfilter/nf_conntrack_max" ]; then
    CT_CNT="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
    CT_MAX="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)"
    if [ "$CT_MAX" -gt 0 ] 2>/dev/null; then
        CT_PCT=$((CT_CNT * 100 / CT_MAX))
        if [ "$CT_PCT" -ge 85 ]; then
            log_fail "ВНИМАНИЕ: Таблица conntrack заполнена на ${CT_PCT}% ($CT_CNT / $CT_MAX)!"
            log_warn "Роутер сбрасывает новые UDP-сессии NAT hole punching! Увеличьте nf_conntrack_max или снизьте тайм-ауты."
        else
            log_ok "Таблица отслеживания соединений conntrack: $CT_CNT / $CT_MAX (${CT_PCT}% занято)"
        fi
    fi
fi

# 4.2 UDP Socket Buffer Drops (/proc/net/snmp)
if [ -f "/proc/net/snmp" ]; then
    # Явно читаем строку заголовка и строку данных по имени "Udp:",
    # чтобы не зависеть от grep -A поведения на busybox (может вернуть только одну строку)
    SNMP_HDR="$(grep '^Udp:' /proc/net/snmp | head -n 1)"
    SNMP_VAL="$(grep '^Udp:' /proc/net/snmp | tail -n 1)"
    if [ -n "$SNMP_HDR" ] && [ "$SNMP_HDR" != "$SNMP_VAL" ]; then
        # Находим индекс нужного поля по имени в строке заголовка
        get_snmp_col() {
            FIELD="$1"
            HDR="$SNMP_HDR"
            VAL="$SNMP_VAL"
            # Нумерация с 1, первый столбец — "Udp:" (пропускаем)
            COL_IDX="$(echo "$HDR" | awk -v f="$FIELD" '{for(i=1;i<=NF;i++){if($i==f){print i; exit}}}')"
            if [ -n "$COL_IDX" ]; then
                echo "$VAL" | awk -v c="$COL_IDX" '{print $c}'
            else
                echo ""
            fi
        }
        IN_PKTS="$(get_snmp_col InDatagrams)"
        IN_ERRS="$(get_snmp_col InErrors)"
        RCV_ERRS="$(get_snmp_col RcvbufErrors)"
        log_info "Статистика UDP ядра: Получено=$IN_PKTS, InErrors=$IN_ERRS, RcvbufErrors=$RCV_ERRS"
        if [ -n "$RCV_ERRS" ] && [ "$RCV_ERRS" -gt 500 ] 2>/dev/null; then
            log_warn "Высокое число ошибок буфера UDP (RcvbufErrors: $RCV_ERRS). Ядро отбрасывает входящие датаграммы из-за нехватки SO_RCVBUF!"
        else
            log_ok "Буферы сокетов UDP ядра в норме (нет массового сброса пакетов)"
        fi
    elif [ -n "$SNMP_HDR" ]; then
        # busybox: обе строки одинаковые — grep вернул только одну; пробуем sed
        SNMP_HDR2="$(sed -n '/^Udp:/{N;p}' /proc/net/snmp 2>/dev/null | head -n 1)"
        SNMP_VAL2="$(sed -n '/^Udp:/{N;p}' /proc/net/snmp 2>/dev/null | tail -n 1)"
        if [ -n "$SNMP_HDR2" ] && [ "$SNMP_HDR2" != "$SNMP_VAL2" ]; then
            IN_PKTS="$(echo "$SNMP_VAL2" | awk '{print $2}')"
            RCV_ERRS="$(echo "$SNMP_VAL2" | awk '{print $5}')"
            log_info "Статистика UDP ядра (busybox fallback): Получено=$IN_PKTS, RcvbufErrors=$RCV_ERRS"
            if [ -n "$RCV_ERRS" ] && [ "$RCV_ERRS" -gt 500 ] 2>/dev/null; then
                log_warn "Высокое число ошибок буфера UDP (RcvbufErrors: $RCV_ERRS)."
            else
                log_ok "Буферы сокетов UDP ядра в норме"
            fi
        else
            log_info "Статистика UDP /proc/net/snmp: недоступна на данной платформе"
        fi
    fi
fi


# 5. Маршрутизация
log_section "5. ТАБЛИЦЫ МАРШРУТИЗАЦИИ И ПРАВИЛА (IP ROUTE / IP RULE)"

log_info "Таблица маршрутов:"
if command -v ip >/dev/null 2>&1; then
    ip route show table main 2>/dev/null | grep -E 'nb0|10\.|100\.64' || ip route show 2>/dev/null | grep -E 'nb0|10\.|100\.64'
    ip route show table main >> "$REPORT_FILE" 2>&1
    # Авто-очистка устаревших правил старых подсетей
    if [ -n "$IP_ADDR" ] && ! echo "$IP_ADDR" | grep -q '^10\.123\.111\.'; then
        if ip rule show 2>/dev/null | grep -q '10\.123\.111\.'; then
            ip rule del to 10.123.111.0/24 2>/dev/null || true
            ip rule del from 10.123.111.0/24 2>/dev/null || true
        fi
    fi
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
MY_PUB_IP=""
MY_STUN=""
MY_VER=""

if [ -n "$STATUS_JSON" ]; then
    log_ok "Локальный API отвечает (HTTP 200)"
    ACT_PROF="$(echo "$STATUS_JSON" | grep -o '"active_profile":"[^"]*' | cut -d'"' -f4)"
    MQTT_TOPIC="$(echo "$STATUS_JSON" | grep -o '"mqtt_topic":"[^"]*' | cut -d'"' -f4)"
    PEERS_CNT="$(echo "$STATUS_JSON" | grep -o '"peers_count":[0-9]*' | cut -d':' -f2)"
    MY_PUB_IP="$(echo "$STATUS_JSON" | grep -o '"public_ip":"[^"]*' | cut -d'"' -f4)"
    MY_STUN="$(echo "$STATUS_JSON" | grep -o '"stun_addr":"[^"]*' | cut -d'"' -f4)"
    MY_VER="$(echo "$STATUS_JSON" | grep -o '"version":"v[^"]*' | cut -d'"' -f4)"
    
    [ -n "$ACT_PROF" ] && log_info "Активный профиль сети: $ACT_PROF"
    [ -n "$MQTT_TOPIC" ] && log_info "Сигнальный топик: $MQTT_TOPIC"
    [ -n "$MY_PUB_IP" ] && log_info "Внешний IP: $MY_PUB_IP | STUN: $MY_STUN | Версия: $MY_VER"
    [ -n "$PEERS_CNT" ] && log_info "Количество обнаруженных пиров: $PEERS_CNT"
    echo "API Status: $STATUS_JSON" >> "$REPORT_FILE"
    
    PEERS_JSON="$(HTTP_GET "http://127.0.0.1:8080/api/peers")"
    if [ -n "$PEERS_JSON" ]; then
        log_section "8. СПИСОК ПОДКЛЮЧЕННЫХ ПИРОВ"
        echo "$PEERS_JSON" >> "$REPORT_FILE"
    fi
else
    log_warn "Локальный API http://127.0.0.1:8080 недоступен"
fi

# 9. Глубокий анализ NAT, CGNAT, Path MTU, ТСПУ/DPI и причин Relay
log_section "9. ГЛУБОКИЙ АНАЛИЗ NAT, CGNAT, ТСПУ/DPI И ПРИЧИН RELAY"

# 9.1 Multi-STUN триангуляция и RFC 6598 CGNAT
log_info "[9.1] Классификация внешнего IP и CGNAT подсети:"
if [ -n "$MY_PUB_IP" ]; then
    if echo "$MY_PUB_IP" | grep -qE '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.'; then
        log_warn "[RFC 6598] Ваш внешний IP ($MY_PUB_IP) принадлежит операторскому пулу Carrier-Grade NAT (100.64.0.0/10)!"
    else
        log_ok "Публичный IP хоста: $MY_PUB_IP"
    fi
fi
if [ -n "$MY_STUN" ]; then
    log_info "STUN эндпоинт по данным демона: $MY_STUN"
fi

# 9.2 Path MTU (PMTU) Discovery
log_info "[9.2] Проверка Path MTU (PMTU) и нефрагментированного прохождения пакетов:"
for MTU_TEST in 1420 1360 1280; do
    PAYLOAD_SIZE=$((MTU_TEST - 28))
    if ping -c 1 -W 1 -M do -s $PAYLOAD_SIZE 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -W 1 -M do -s $PAYLOAD_SIZE 1.1.1.1 >/dev/null 2>&1; then
        log_ok "MTU $MTU_TEST (Payload $PAYLOAD_SIZE байт): УСПЕШНО без фрагментации"
    else
        log_warn "MTU $MTU_TEST: ТРЕБУЕТСЯ ФРАГМЕНТАЦИЯ (или блокируется промежуточными маршрутизаторами)"
    fi
done

# 9.3 Дифференциальная диагностика ТСПУ / DPI (WireGuard vs Random vs QUIC Initial)
log_info "[9.3] Дифференциальная диагностика фильтрации ТСПУ / DPI:"
TMP_DPI_DIR="/tmp/tspu_diag_$$"
mkdir -p "$TMP_DPI_DIR"

# 1. WireGuard Mock (148B)
printf '\x01\x00\x00\x00' > "$TMP_DPI_DIR/wg.bin"
dd if=/dev/urandom bs=144 count=1 >> "$TMP_DPI_DIR/wg.bin" 2>/dev/null

# 2. Random UDP Noise (148B)
dd if=/dev/urandom of="$TMP_DPI_DIR/rand.bin" bs=148 count=1 2>/dev/null

# 3. QUIC Initial Mock (1200B)
printf '\xc0\x00\x00\x00\x01\x08\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00' > "$TMP_DPI_DIR/quic.bin"
dd if=/dev/zero bs=1 count=1184 >> "$TMP_DPI_DIR/quic.bin" 2>/dev/null

# Вспомогательная функция: отправка UDP через /dev/udp (bash built-in, без nc)
udp_send_devudp() {
    BIN_FILE="$1"
    DST_IP="$2"
    DST_PORT="$3"
    # /dev/udp доступен только в bash (не в dash/sh на busybox)
    # Пробуем: exec с таймаутом через subshell
    ( bash -c "exec 3>/dev/udp/$DST_IP/$DST_PORT 2>/dev/null && cat '$BIN_FILE' >&3 && sleep 0.3; exec 3>&-" ) 2>/dev/null
    return $?
}

NC_AVAILABLE=0
DEVUDP_AVAILABLE=0
command -v nc >/dev/null 2>&1 && NC_AVAILABLE=1
# Проверяем /dev/udp (только bash, не busybox sh)
bash -c 'exec 3>/dev/udp/1.1.1.1/53 2>/dev/null && exec 3>&-' 2>/dev/null && DEVUDP_AVAILABLE=1

if [ "$NC_AVAILABLE" -eq 1 ] || [ "$DEVUDP_AVAILABLE" -eq 1 ]; then
    for TEST_P in 443 3478 51820; do
        if [ "$NC_AVAILABLE" -eq 1 ]; then
            timeout 1 nc -u -w 1 1.1.1.1 "$TEST_P" < "$TMP_DPI_DIR/wg.bin" >/dev/null 2>&1;   WG_STAT=$?
            timeout 1 nc -u -w 1 1.1.1.1 "$TEST_P" < "$TMP_DPI_DIR/rand.bin" >/dev/null 2>&1; RAND_STAT=$?
            timeout 1 nc -u -w 1 1.1.1.1 "$TEST_P" < "$TMP_DPI_DIR/quic.bin" >/dev/null 2>&1; QUIC_STAT=$?
        else
            udp_send_devudp "$TMP_DPI_DIR/wg.bin" 1.1.1.1 "$TEST_P";   WG_STAT=$?
            udp_send_devudp "$TMP_DPI_DIR/rand.bin" 1.1.1.1 "$TEST_P"; RAND_STAT=$?
            udp_send_devudp "$TMP_DPI_DIR/quic.bin" 1.1.1.1 "$TEST_P"; QUIC_STAT=$?
        fi
        log_info "Порт UDP $TEST_P -> WG(148B): exit $WG_STAT | Rand(148B): exit $RAND_STAT | QUIC(1200B): exit $QUIC_STAT"
    done
else
    log_warn "[9.3] DPI-тест пропущен: nc (netcat) и /dev/udp (bash) недоступны на данной платформе (KeeneticOS busybox sh)"
fi
rm -rf "$TMP_DPI_DIR"


# 9.4 Матрица совместимости пиров и причины работы через Relay
log_info "[9.4] Матрица совместимости пиров и анализ причин Relay:"

if [ -n "$PEERS_JSON" ] && echo "$PEERS_JSON" | grep -q '"virtual_ip"'; then
    TMP_ANALYSIS="$(mktemp 2>/dev/null || echo "/tmp/nb_diag_an_$$")"
    echo "$PEERS_JSON" | tr '}' '\n' > "$TMP_ANALYSIS"
    
    while read -r p_line; do
        VIP="$(echo "$p_line" | grep -o '"virtual_ip":"[^"]*' | cut -d'"' -f4)"
        [ -z "$VIP" ] && continue
        
        DEV_NAME="$(echo "$p_line" | grep -o '"device_name":"[^"]*' | cut -d'"' -f4)"
        DEV_ID="$(echo "$p_line" | grep -o '"device_id":"[^"]*' | cut -d'"' -f4)"
        [ -z "$DEV_NAME" ] && DEV_NAME="$DEV_ID"
        
        P_PUB_IP="$(echo "$p_line" | grep -o '"public_ip":"[^"]*' | cut -d'"' -f4)"
        P_NAT="$(echo "$p_line" | grep -o '"nat_type":"[^"]*' | cut -d'"' -f4)"
        P_VER="$(echo "$p_line" | grep -o '"version":"v[^"]*' | cut -d'"' -f4)"
        P_PROBES="$(echo "$p_line" | grep -o '"probe_count":[0-9]*' | cut -d':' -f2)"
        [ -z "$P_PROBES" ] && P_PROBES=0
        P_DIRECT="$(echo "$p_line" | grep -o '"direct_p2p":true' | cut -d':' -f2)"
        P_EP="$(echo "$p_line" | grep -o '"active_endpoint":"[^"]*' | cut -d'"' -f4)"
        P_PING="$(echo "$p_line" | grep -o '"ping_ms":[0-9]*' | cut -d':' -f2)"
        [ -z "$P_PING" ] && P_PING=0
        
        printf "\n  %bПир '%s' (VIP: %s):%b\n" "$C_CYAN" "$DEV_NAME" "$VIP" "$C_RESET"
        
        if [ "$P_DIRECT" = "true" ]; then
            log_ok "Прямой P2P установлен (Endpoint: $P_EP, Ping: ${P_PING} ms)"
            continue
        fi
        
        log_warn "Текущий статус: Relay (прямой P2P не установлен)"
        
        # Проверка 1: Одно Wi-Fi / NAT Hairpinning
        if [ -n "$MY_PUB_IP" ] && [ -n "$P_PUB_IP" ] && [ "$MY_PUB_IP" = "$P_PUB_IP" ]; then
            log_fail "  [!] ПРИЧИНА [Same Wi-Fi / NAT Loopback Blocked]:"
            log_warn "      Пир '$DEV_NAME' и данный хост имеют ОДИНАКОВЫЙ внешний IP ($MY_PUB_IP)!"
            log_info "      -> Они находятся в ОДНОЙ локальной сети / Wi-Fi роутере."
            log_info "      -> Роутер блокирует обратный трафик (NAT Hairpinning) при обращении к собственному внешнему порту."
            log_info "      -> Решение: Убедитесь, что в Wi-Fi сети отключена изоляция клиентов (AP Isolation = Off), и обмен идет по локальным IP (LAN candidates)."
        fi
        
        # Проверка 2: ТСПУ / Блокировка UDP проб
        if [ "$P_PROBES" -gt 15 ] 2>/dev/null; then
            log_fail "  [!] ПРИЧИНА [ТСПУ / Блокировка UDP / Закрытый порт]:"
            log_warn "      Отправлено $P_PROBES UDP-проб пробива NAT, но ни одного ответа не получено!"
            log_info "      -> Сигнальные маяки через MQTT доходят (узел виден), но UDP пакеты сбрасываются ТСПУ (DPI) на трансграничном стыке или файрволом."
            log_info "      -> Решение: Убедитесь, что у обоих узлов активирован строгий профиль AmneziaWG (AWG 3.1 strict) с обфускацией заголовков (H1..H4, S1..S4, Jc)."
        fi
        
        # Проверка 3: Симметричный NAT
        if echo "$P_NAT" | grep -qi "symmetric"; then
            log_warn "  [!] ФАКТОР [Symmetric NAT у пира]:"
            log_info "      Удаленный узел находится за Symmetric NAT / мобильным CGNAT ($P_NAT)."
            log_info "      Роутер меняет внешний порт для каждого назначения, что препятствует прямому пробиву."
        fi
        
        # Проверка 4: Несовместимость версий
        if [ -n "$P_VER" ] && [ -n "$MY_VER" ] && [ "$P_VER" != "$MY_VER" ]; then
            log_warn "  [!] ФАКТОР [Версия пира отличается]:"
            log_warn "      Пир использует версию '$P_VER', а данный узел — '$MY_VER'."
            log_info "      Рекомендуется обновить все узлы до одного актуального билда."
        fi
        
        # Проверка 5: Несовпадение AmneziaWG
        P_HAS_AWG="$(echo "$p_line" | grep -o '"h1":' || echo "")"
        MY_HAS_AWG="$(echo "$STATUS_JSON" | grep -o '"awg_enabled":true' || echo "")"
        if [ -z "$MY_HAS_AWG" ]; then
            MY_HAS_AWG="$(echo "$STATUS_JSON" | grep -o '"h1":' || echo "")"
        fi
        P_MISMATCH="$(echo "$p_line" | grep -o '"awg_mismatch":true' || echo "")"
        if [ -n "$P_MISMATCH" ]; then
            log_warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: параметры обфускации AWG 3.1 различаются!"
        elif [ -n "$P_HAS_AWG" ] && [ -z "$MY_HAS_AWG" ]; then
            log_warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: на удаленном узле AWG включен, а на локальном выключен!"
        elif [ -z "$P_HAS_AWG" ] && [ -n "$MY_HAS_AWG" ]; then
            log_warn "  [!] ФАКТОР [Рассогласование AmneziaWG]: на локальном узле AWG включен, а на удаленном выключен!"
        fi
        
    done < "$TMP_ANALYSIS"
    rm -f "$TMP_ANALYSIS"
fi

# 10. Сквозной ICMP Ping тест ко всем обнаруженным пирам
log_section "10. СКВОЗНОЙ ТЕСТ ICMP PING ДО ВСЕХ ОБНАРУЖЕННЫХ ПИРОВ"

test_ping() {
    TARGET_IP="$1"
    NAME="$2"
    CLEAN_IP="$(echo "$TARGET_IP" | tr -s ' \t\r\n' ' ' | cut -d' ' -f1 | cut -d'/' -f1 | tr -d ' ')"
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

# 2. Динамический пинг всех зарегистрированных пиров из API
PEERS_PINGED=0
if [ -n "$PEERS_JSON" ] && echo "$PEERS_JSON" | grep -q '"virtual_ip"'; then
    TMP_PEERS="$(mktemp 2>/dev/null || echo "/tmp/nb_diag_peers_$$")"
    echo "$PEERS_JSON" | tr '}' '\n' > "$TMP_PEERS"
    while read -r p_line; do
        VIP="$(echo "$p_line" | grep -o '"virtual_ip":"[^"]*' | cut -d'"' -f4)"
        DEV_NAME="$(echo "$p_line" | grep -o '"device_name":"[^"]*' | cut -d'"' -f4)"
        DEV_ID="$(echo "$p_line" | grep -o '"device_id":"[^"]*' | cut -d'"' -f4)"
        [ -z "$DEV_NAME" ] && DEV_NAME="$DEV_ID"
        CLEAN_VIP="$(echo "$VIP" | awk -F'/' '{print $1}' | tr -d ' ')"
        if [ -n "$CLEAN_VIP" ] && [ "$CLEAN_VIP" != "$IP_ADDR" ] && [ "$CLEAN_VIP" != "0.0.0.0" ]; then
            test_ping "$CLEAN_VIP" "$DEV_NAME"
            PEERS_PINGED=$((PEERS_PINGED + 1))
        fi
    done < "$TMP_PEERS"
    rm -f "$TMP_PEERS"
fi

# Если удалённых пиров в API пока нет:
if [ "$PEERS_PINGED" -eq 0 ]; then
    log_info "Удалённые пиры в реестре API пока не зарегистрированы (ожидание маяков signaling)"
    if [ -n "$IP_ADDR" ]; then
        SUBNET_PREF="$(echo "$IP_ADDR" | awk -F'.' '{print $1"."$2"."$3}')"
        for host_num in 1 2; do
            CANDIDATE="${SUBNET_PREF}.${host_num}"
            if [ "$CANDIDATE" != "$IP_ADDR" ]; then
                test_ping "$CANDIDATE" "Узел подсети ${SUBNET_PREF}.0/24 (Fallback)"
            fi
        done
    fi
fi

printf "\n%b======================================================================%b\n" "$C_GREEN$C_BOLD" "$C_RESET"
printf "✓ Диагностический отчет сохранен в: %s\n" "$REPORT_FILE"
printf "%b======================================================================%b\n\n" "$C_GREEN$C_BOLD" "$C_RESET"
cat "$REPORT_FILE"
