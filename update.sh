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
    DEFAULT_TAG="v1.1.0"

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
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${DEFAULT_TAG}/natbypass-${DEFAULT_TAG}-${BIN_SUFFIX}"
    FALLBACK_URL="https://github.com/${REPO}/releases/latest/download/natbypass-${DEFAULT_TAG}-${BIN_SUFFIX}"

    echo ">> Загрузка новой версии (${BIN_SUFFIX})..."
    DOWNLOADED=0

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_BIN}" 2>/dev/null && DOWNLOADED=1 || \
        curl -fsSL "${FALLBACK_URL}" -o "${TMP_BIN}" 2>/dev/null && DOWNLOADED=1 || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${DOWNLOAD_URL}" -O "${TMP_BIN}" 2>/dev/null && DOWNLOADED=1 || \
        wget -q "${FALLBACK_URL}" -O "${TMP_BIN}" 2>/dev/null && DOWNLOADED=1 || true
    fi

    if [ "$DOWNLOADED" -eq 0 ] || [ ! -s "${TMP_BIN}" ]; then
        print_red "[!] Ошибка загрузки обновления. Проверьте интернет-соединение."
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