#!/bin/sh
# ==============================================================================
#  NatBypass — Universal Uninstaller for Keenetic, OpenWrt & Linux
# ==============================================================================
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
#    or with full data purge:
#    curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
# ==============================================================================

set -e

main() {
    print_purple() { printf "\033[0;35m%s\033[0m\n" "$1"; }
    print_cyan()   { printf "\033[0;36m%s\033[0m\n" "$1"; }
    print_green()  { printf "\033[0;32m%s\033[0m\n" "$1"; }
    print_yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
    print_red()    { printf "\033[0;31m%s\033[0m\n" "$1"; }
    print_bold()   { printf "\033[1;37m%s\033[0m\n" "$1"; }

    echo "--------------------------------------------------------------"
    print_bold ">> Удаление NatBypass Mesh Network"
    echo "--------------------------------------------------------------"

    # 1. Stop and remove services
    echo ">> Остановка активных процессов и служб..."
    
    # Keenetic Entware
    if [ -f /opt/etc/init.d/S99natbypass ]; then
        /opt/etc/init.d/S99natbypass stop >/dev/null 2>&1 || true
        rm -f /opt/etc/init.d/S99natbypass
        print_green "✓ Служба Entware удалена (/opt/etc/init.d/S99natbypass)"
    fi

    # OpenWrt Procd
    if [ -f /etc/init.d/natbypass ]; then
        /etc/init.d/natbypass stop >/dev/null 2>&1 || true
        /etc/init.d/natbypass disable >/dev/null 2>&1 || true
        rm -f /etc/init.d/natbypass
        print_green "✓ Служба OpenWrt удалена (/etc/init.d/natbypass)"
    fi

    # Linux systemd
    if [ -f /etc/systemd/system/natbypass.service ]; then
        systemctl stop natbypass >/dev/null 2>&1 || true
        systemctl disable natbypass >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/natbypass.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        print_green "✓ Служба systemd удалена (/etc/systemd/system/natbypass.service)"
    fi

    # Kill any remaining instances
    killall natbypass 2>/dev/null || true

    # 2. Remove Binaries
    echo ">> Удаление исполняемых файлов..."
    rm -f /opt/bin/natbypass /opt/usr/bin/natbypass /usr/local/bin/natbypass /usr/bin/natbypass
    print_green "✓ Бинарные файлы natbypass удалены"

    # 3. Remove PID files and logs
    rm -f /var/run/natbypass.pid /opt/var/log/natbypass.log /var/log/natbypass.log

    # 4. Cleanup configs if --purge specified
    if [ "$1" = "--purge" ] || [ "$1" = "-p" ]; then
        rm -rf /opt/etc/natbypass /etc/natbypass
        print_green "✓ Конфигурация и ключи полностью удалены (--purge)"
    else
        print_yellow "💡 Конфигурация сохранена (/opt/etc/natbypass или /etc/natbypass)."
        print_yellow "   Для полного удаления вместе с конфигами запустите:"
        print_cyan   "   curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge"
    fi

    echo "--------------------------------------------------------------"
    print_green "🎉 NatBypass успешно удален из системы!"
    echo "--------------------------------------------------------------"
}

main "$@"