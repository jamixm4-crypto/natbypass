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
    DEFAULT_STABLE="v1.9.221"
    DEFAULT_BETA="v1.9.222-beta.14"
    BETA_MODE=-1

    # Parse CLI flags
    for arg in "$@"; do
        case "$arg" in
            --beta|-b|--prerelease)
                BETA_MODE=1
                ;;
            --stable|-s)
                BETA_MODE=0
                ;;
        esac
    done

    print_purple() { printf "\033[0;35m%s\033[0m\n" "$1"; }
    print_cyan()   { printf "\033[0;36m%s\033[0m\n" "$1"; }
    print_green()  { printf "\033[0;32m%s\033[0m\n" "$1"; }
    print_yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
    print_red()    { printf "\033[0;31m%s\033[0m\n" "$1"; }
    print_bold()   { printf "\033[1;37m%s\033[0m\n" "$1"; }

    echo "--------------------------------------------------------------"
    print_bold ">> NatBypass Mesh Network — Универсальный авто-обновлятор"
    echo "--------------------------------------------------------------"

    # Find Target Binary Path first (needed to check running version track)
    TARGET_BIN=""
    if [ -f /opt/bin/natbypass ]; then
        TARGET_BIN="/opt/bin/natbypass"
    elif [ -f /usr/bin/natbypass ]; then
        TARGET_BIN="/usr/bin/natbypass"
    elif [ -f /usr/local/bin/natbypass ]; then
        TARGET_BIN="/usr/local/bin/natbypass"
    elif command -v natbypass >/dev/null 2>&1; then
        TARGET_BIN=$(command -v natbypass)
    else
        TARGET_BIN="/opt/bin/natbypass"
    fi

    # Auto-detect beta mode if user did NOT specify --stable or --beta explicitly
    if [ "$BETA_MODE" -eq -1 ]; then
        if [ -x "${TARGET_BIN}" ]; then
            INSTALLED_VER=$("${TARGET_BIN}" version 2>/dev/null || "${TARGET_BIN}" --version 2>/dev/null || true)
            case "${INSTALLED_VER}" in
                *beta*|*rc*|*-*)
                    BETA_MODE=1
                    print_cyan "ℹ️ Обнаружена установленная тестовая сборка (${INSTALLED_VER}). Включаем Beta-канал."
                    ;;
                *)
                    BETA_MODE=0
                    ;;
            esac
        else
            BETA_MODE=0
        fi

        # Also check config.yaml for beta_channel setting if not determined yet
        if [ "$BETA_MODE" -eq 0 ]; then
            for cfg in /opt/etc/natbypass/config.yaml /etc/natbypass/config.yaml ./config.yaml; do
                if [ -f "$cfg" ] && grep -q "beta_channel: true" "$cfg" 2>/dev/null; then
                    BETA_MODE=1
                    break
                fi
            done
        fi
    fi

    # Resolve latest release tag (with jsDelivr CDN & ghproxy fallbacks for blocked regions)
    TAG=""
    if [ "$BETA_MODE" -eq 1 ]; then
        print_yellow ">> Канал обновлений: BETA / PRE-RELEASE"
        # 1. Try jsDelivr mirror manifest (fastest and unblocked in RU)
        TAG=$(curl -s "https://cdn.jsdelivr.net/gh/${REPO}@main/mirror/releases/latest-beta.json" 2>/dev/null | grep '"version":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
        # 2. Try GitHub API
        if [ -z "$TAG" ]; then
            TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases" 2>/dev/null | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
        fi
        # 3. Try ghproxy GitHub API
        if [ -z "$TAG" ]; then
            TAG=$(curl -s "https://ghproxy.net/https://raw.githubusercontent.com/${REPO}/main/mirror/releases/latest-beta.json" 2>/dev/null | grep '"version":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
        fi
        [ -z "$TAG" ] && TAG="${DEFAULT_BETA}"
    else
        print_bold ">> Канал обновлений: STABLE"
        # 1. Try jsDelivr mirror manifest
        TAG=$(curl -s "https://cdn.jsdelivr.net/gh/${REPO}@main/mirror/releases/latest.json" 2>/dev/null | grep '"version":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
        # 2. Try GitHub API
        if [ -z "$TAG" ]; then
            TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
        fi
        # 3. Try ghproxy
        if [ -z "$TAG" ]; then
            TAG=$(curl -s "https://ghproxy.net/https://raw.githubusercontent.com/${REPO}/main/mirror/releases/latest.json" 2>/dev/null | grep '"version":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
        fi
        [ -z "$TAG" ] && TAG="${DEFAULT_STABLE}"
    fi

    echo "--------------------------------------------------------------"
    printf "✓ Целевой релиз:          "; print_green "${TAG}"
    printf "✓ Путь к программе:       "; print_cyan "${TARGET_BIN}"

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
        armv7l|armv6l|armv7|armhf|arm)
            BIN_SUFFIX="router-armv7"
            ARCH_DESC="ARMv7 32-bit (Keenetic Hopper/Voyager, Cortex-A7)"
            ;;

        *)
            BIN_SUFFIX="linux-amd64"
            ARCH_DESC="Generic (${RAW_ARCH})"
            ;;
    esac

    printf "✓ Архитектура устройства: "; print_cyan "${ARCH_DESC}"

    # 2. Build Candidate Download URLs (Direct + ghproxy + gh-proxy)
    TMP_BIN="/tmp/natbypass.new"
    rm -f "${TMP_BIN}"

    ALT_SUFFIX=""
    case "${BIN_SUFFIX}" in
        router-mipsle) ALT_SUFFIX="keenetic-mipsle" ;;
        router-mips)   ALT_SUFFIX="linux-mips" ;;
        openwrt-armv7) ALT_SUFFIX="router-armv7" ;;
    esac

    DL_NAMES="natbypass-${BIN_SUFFIX}"
    if [ -n "$ALT_SUFFIX" ]; then
        DL_NAMES="${DL_NAMES} natbypass-${ALT_SUFFIX}"
    fi

    echo ">> Загрузка новой версии (${TAG})..."
    DOWNLOADED=0

    for name in $DL_NAMES; do
        CANDIDATE_URLS="
https://github.com/${REPO}/releases/download/${TAG}/${name}
https://ghproxy.net/https://github.com/${REPO}/releases/download/${TAG}/${name}
https://gh-proxy.com/https://github.com/${REPO}/releases/download/${TAG}/${name}
"
        for u in $CANDIDATE_URLS; do
            [ -z "$u" ] && continue
            if command -v curl >/dev/null 2>&1; then
                if curl -fsSL --connect-timeout 8 --max-time 180 "$u" -o "${TMP_BIN}" 2>/dev/null && [ -s "${TMP_BIN}" ]; then
                    if head -c 4 "${TMP_BIN}" 2>/dev/null | grep -q 'ELF'; then
                        DOWNLOADED=1
                        break 2
                    fi
                    rm -f "${TMP_BIN}"
                fi
            elif command -v wget >/dev/null 2>&1; then
                if wget -q --timeout=8 -t 2 "$u" -O "${TMP_BIN}" 2>/dev/null && [ -s "${TMP_BIN}" ]; then
                    if head -c 4 "${TMP_BIN}" 2>/dev/null | grep -q 'ELF'; then
                        DOWNLOADED=1
                        break 2
                    fi
                    rm -f "${TMP_BIN}"
                fi
            fi
        done
    done

    if [ "$DOWNLOADED" -eq 0 ] || [ ! -s "${TMP_BIN}" ]; then
        print_red "[!] Ошибка: не удалось скачать исполняемый файл обновления."
        print_yellow "Проверьте подключение к сети и доступность релизов на GitHub / зеркалах."
        rm -f "${TMP_BIN}"
        exit 1
    fi

    chmod 0755 "${TMP_BIN}"

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
    elif command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/natbypass.service ]; then
        systemctl daemon-reload
        systemctl restart natbypass || systemctl start natbypass
        print_green "✓ Служба systemd перезапущена."
    else
        killall natbypass 2>/dev/null || true
        sleep 1
        nohup "${TARGET_BIN}" start >/dev/null 2>&1 &
        print_green "✓ Демон NatBypass перезапущен в фоне."
    fi

    echo "--------------------------------------------------------------"
    print_green "🎉 Обновление успешно завершено! Все настройки и ключи сохранены."
    echo "--------------------------------------------------------------"
}

main "$@"