#!/bin/sh
# ==============================================================================
#  NatBypass — Universal Uninstaller & Config Reset for Keenetic, OpenWrt & Linux
# ==============================================================================
#  Usage:
#    1. Удаление без удаления настроек:
#       curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
#
#    2. Полное удаление программы вместе со всеми конфигурациями и ключами:
#       curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
#
#    3. Только очистка / сброс конфигурации (бинарники и служба остаются):
#       curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
# ==============================================================================

set -e

main() {
    print_purple() { printf "\033[0;35m%s\033[0m\n" "$1"; }
    print_cyan()   { printf "\033[0;36m%s\033[0m\n" "$1"; }
    print_green()  { printf "\033[0;32m%s\033[0m\n" "$1"; }
    print_yellow() { printf "\033[1;33m%s\033[0m\n" "$1"; }
    print_red()    { printf "\033[0;31m%s\033[0m\n" "$1"; }
    print_bold()   { printf "\033[1;37m%s\033[0m\n" "$1"; }

    # Режим: Сброс / Очистка конфигурации
    if [ "$1" = "--reset-config" ] || [ "$1" = "-r" ] || [ "$1" = "--clean-config" ]; then
        echo "--------------------------------------------------------------"
        print_bold ">> Сброс и очистка конфигурации NatBypass"
        echo "--------------------------------------------------------------"
        echo ">> Остановка активных служб перед очисткой..."

        if [ -f /opt/etc/init.d/S99natbypass ]; then
            /opt/etc/init.d/S99natbypass stop >/dev/null 2>&1 || true
        fi
        if [ -f /etc/init.d/natbypass ]; then
            /etc/init.d/natbypass stop >/dev/null 2>&1 || true
        fi
        if [ -f /etc/systemd/system/natbypass.service ]; then
            systemctl stop natbypass >/dev/null 2>&1 || true
        fi
        killall natbypass 2>/dev/null || true

        echo ">> Удаление профилей, ключей шифрования и кэша..."
        rm -rf /opt/etc/natbypass/* /etc/natbypass/* 2>/dev/null || true
        rm -f /opt/var/run/.natbypass_sessions.json /var/run/natbypass/.natbypass_sessions.json /tmp/.natbypass_sessions.json 2>/dev/null || true
        rm -f /var/run/natbypass.pid /opt/var/run/natbypass.pid 2>/dev/null || true

        print_green "✓ Все файлы конфигурации (config.yaml, ключи WireGuard, профили) очищены."

        echo ">> Перезапуск службы со свежей конфигурацией по умолчанию..."
        if [ -f /opt/etc/init.d/S99natbypass ]; then
            /opt/etc/init.d/S99natbypass start >/dev/null 2>&1 || true
            print_green "✓ Служба Keenetic Entware запущена с новым DeviceID и профилем."
        elif [ -f /etc/init.d/natbypass ]; then
            /etc/init.d/natbypass start >/dev/null 2>&1 || true
            print_green "✓ Служба OpenWrt запущена с новым DeviceID и профилем."
        elif [ -f /etc/systemd/system/natbypass.service ]; then
            systemctl start natbypass >/dev/null 2>&1 || true
            print_green "✓ Служба systemd запущена с новым DeviceID и профилем."
        else
            print_yellow "💡 Служба не установлена в автозагрузку. Запустите natbypass вручную."
        fi

        echo "--------------------------------------------------------------"
        print_green "🎉 Конфигурация успешно сброшена на заводские настройки!"
        echo "--------------------------------------------------------------"
        return 0
    fi

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
    rm -f /opt/bin/natbypass /opt/sbin/natbypass /opt/usr/bin/natbypass /usr/local/bin/natbypass /usr/bin/natbypass /usr/local/sbin/natbypass
    print_green "✓ Бинарные файлы natbypass удалены"

    # 3. Remove PID files, sessions and logs
    rm -f /var/run/natbypass.pid /opt/var/run/natbypass.pid /opt/var/log/natbypass.log /var/log/natbypass.log
    rm -f /opt/var/run/.natbypass_sessions.json /var/run/natbypass/.natbypass_sessions.json /tmp/.natbypass_sessions.json 2>/dev/null || true

    # 4. Cleanup configs if --purge specified
    if [ "$1" = "--purge" ] || [ "$1" = "-p" ]; then
        rm -rf /opt/etc/natbypass /etc/natbypass
        print_green "✓ Конфигурация, профили и ключи полностью удалены (--purge)"
    else
        print_yellow "💡 Конфигурация сохранена (/opt/etc/natbypass или /etc/natbypass)."
        print_yellow "   Для полного удаления вместе с конфигами и ключами выполните:"
        print_cyan   "   curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge"
        print_yellow "   Или для очистки только конфигурации (без удаления бинарника):"
        print_cyan   "   curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config"
    fi

    echo "--------------------------------------------------------------"
    print_green "🎉 NatBypass успешно удален из системы!"
    echo "--------------------------------------------------------------"
}

main "$@"