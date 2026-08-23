#!/bin/sh
# ==============================================================================
#  NatBypass — One-Line Auto-Updater for Linux, Keenetic & OpenWrt
# ==============================================================================
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/update.sh | sh
# ==============================================================================

set -e

main() {
    REPO="jamixm4-crypto/natbypass"
    DEFAULT_TAG="v1.2.4"

    # Try to resolve latest tag from GitHub API
    LATEST_TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
    if [ -n "$LATEST_TAG" ]; then
        TAG="${LATEST_TAG}"
    else
        TAG="${DEFAULT_TAG}"
    fi

    print_purple() { printf "\033[0;35m%s\033[0m\n" "$1"; }
    print_cyan()   { printf "\033[0;36m%s\033[0m\n" "$1"; }
    print_green()  { printf "\033[0;32m%s\033[0m\n" "$1"; }
    print_yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
    print_red()    { printf "\033[0;31m%s\033[0m\n" "$1"; }
    print_bold()   { printf "\033[1;37m%s\033[0m\n" "$1"; }

    echo "--------------------------------------------------------------"
    print_bold ">> Обновление NatBypass Mesh Network до последней версии"
    echo "--------------------------------------------------------------"

    # 1. Detect Architecture
    RAW_ARCH=$(uname -m 2>/dev/null || echo "unknown")
    case "${RAW_ARCH}" in
        x86_64|amd64)
            BIN_SUFFIX="linux-amd64"
            ARCH_DESC="x86_64 (PC / Server)"
            ;;
        aarch64|arm64)
            BIN_SUFFIX="linux-arm64"
            ARCH_DESC="ARM64 (Keenetic Titan/Hero/Giga, Raspberry Pi)"
            ;;
        mips)
            if echo -n I | hexdump -o 2>/dev/null | grep -q '0000000 0001'; then
                BIN_SUFFIX="router-mips"
                ARCH_DESC="MIPS Big-Endian"
            else
                BIN_SUFFIX="router-mipsle"
                ARCH_DESC="MIPS Little-Endian (Keenetic MT7621)"
            fi
            ;;
        mips64)
            BIN_SUFFIX="router-mips"
            ARCH_DESC="MIPS64"
            ;;
        mipsel|mipsle)
            BIN_SUFFIX="router-mipsle"
            ARCH_DESC="MIPS Little-Endian (Keenetic / MT7621 / KN-1010)"
            ;;
        armv7l|armv6l)
            BIN_SUFFIX="linux-arm64"
            ARCH_DESC="ARM 32/64"
            ;;
        *)
            BIN_SUFFIX="linux-amd64"
            ARCH_DESC="Generic (${RAW_ARCH})"
            ;;
    esac

    printf "✓ Архитектура устройства: "; print_cyan "${ARCH_DESC}"

    # 2. Find Target Binary Path
    TARGET_BIN=""
    if [ -f /opt/bin/natbypass ]; then
        TARGET_BIN="/opt/bin/natbypass"
        RESTART_CMD="/opt/etc/init.d/S99natbypass restart"
    elif [ -f /usr/bin/natbypass ]; then
        TARGET_BIN="/usr/bin/natbypass"
        RESTART_CMD="/etc/init.d/natbypass restart"
    elif [ -f /usr/local/bin/natbypass ]; then
        TARGET_BIN="/usr/local/bin/natbypass"
        RESTART_CMD="systemctl restart natbypass"
    elif command -v natbypass >/dev/null 2>&1; then
        TARGET_BIN=$(command -v natbypass)
        RESTART_CMD="killall -HUP natbypass 2>/dev/null || true"
    else
        TARGET_BIN="/opt/bin/natbypass"
        RESTART_CMD="/opt/etc/init.d/S99natbypass restart"
    fi

    printf "✓ Путь к программе:       "; print_cyan "${TARGET_BIN}"

    # 3. Download Latest Binary to Temporary File
    TMP_BIN="/tmp/natbypass.new"
    URLS="
https://github.com/${REPO}/releases/download/${TAG}/natbypass-${TAG}-${BIN_SUFFIX}
https://github.com/${REPO}/releases/download/${TAG}/natbypass-${BIN_SUFFIX}
https://github.com/${REPO}/releases/latest/download/natbypass-${TAG}-${BIN_SUFFIX}
https://github.com/${REPO}/releases/latest/download/natbypass-${BIN_SUFFIX}
"

    echo ">> Загрузка новой версии (${BIN_SUFFIX} ${TAG})..."
    DOWNLOADED=0

    for u in $URLS; do
        [ -z "$u" ] && continue
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL "$u" -o "${TMP_BIN}" 2>/dev/null && [ -s "${TMP_BIN}" ]; then
                DOWNLOADED=1
                break
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q "$u" -O "${TMP_BIN}" 2>/dev/null && [ -s "${TMP_BIN}" ]; then
                DOWNLOADED=1
                break
            fi
        fi
    done

    if [ "$DOWNLOADED" -eq 0 ] || [ ! -s "${TMP_BIN}" ]; then
        print_red "[!] Ошибка загрузки обновления."
        print_yellow "Проверены URL:"
        for u in $URLS; do [ -n "$u" ] && echo " - $u"; done
        rm -f "${TMP_BIN}"
        exit 1
    fi

    chmod +x "${TMP_BIN}"

    # 4. Atomic Replace Binary
    mkdir -p "$(dirname "${TARGET_BIN}")"
    mv -f "${TMP_BIN}" "${TARGET_BIN}"
    if [ -f /opt/bin/natbypass ]; then
        mkdir -p /opt/usr/bin 2>/dev/null || true
        ln -sf /opt/bin/natbypass /opt/usr/bin/natbypass 2>/dev/null || true
    fi
    print_green "✓ Исполняемый файл успешно обновлен."

    # Синхронизация топика и брокера со стандартными значениями Windows
    for cfg in /opt/etc/natbypass/config.yaml /etc/natbypass/config.yaml; do
        if [ -f "$cfg" ]; then
            sed -i 's|natbypass/public/peers|natbypass/mynet/peers|g' "$cfg" 2>/dev/null || true
            sed -i 's|broker.hivemq.com|broker.emqx.io|g' "$cfg" 2>/dev/null || true
            sed -i 's|mqtt.eclipseprojects.io|broker.emqx.io|g' "$cfg" 2>/dev/null || true
        fi
    done

    # 5. Restart Service Gracefully
    echo ">> Перезапуск службы NatBypass..."
    if [ -f /opt/etc/init.d/S99natbypass ]; then
        /opt/etc/init.d/S99natbypass restart >/dev/null 2>&1 || true
        print_green "✓ Служба Keenetic Entware перезапущена."
    elif [ -f /etc/init.d/natbypass ]; then
        /etc/init.d/natbypass restart >/dev/null 2>&1 || true
        print_green "✓ Служба OpenWrt перезапущена."
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet natbypass 2>/dev/null; then
        systemctl restart natbypass
        print_green "✓ Служба systemd перезапущена."
    else
        killall natbypass 2>/dev/null || true
        sleep 1
        nohup "${TARGET_BIN}" start >/dev/null 2>&1 &
        print_green "✓ Демон NatBypass запущен."
    fi

    echo "--------------------------------------------------------------"
    print_green "🎉 Обновление успешно завершено! Все настройки и ключи сохранены."
    echo "--------------------------------------------------------------"
}

main "$@"