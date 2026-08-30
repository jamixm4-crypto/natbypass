#!/bin/bash
# ============================================================
# Миграция на AmneziaWG 3.1 для NatBypass
# ============================================================

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     НатБайпас: Миграция на AmneziaWG 3.1                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  ВНИМАНИЕ!"
echo "После миграции все клиенты должны обновиться до новой версии."
echo "Старые клиенты с AWG 2.0 НЕ СМОГУТ подключиться."
echo ""
read -p "Продолжить? (y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Отмена."
    exit 0
fi

echo ""
echo "📋 Шаг 1: Генерация параметров AWG 3.1..."
natbypass-cli awg generate --preset awg31_strict --output /etc/natbypass/awg31.conf

echo "📋 Шаг 2: Обновление основного конфига..."
natbypass-cli config set wireguard.awg_version "3.1"
natbypass-cli config set wireguard.awg_preset "awg31_strict"
natbypass-cli config set wireguard.header_protection_key "$(openssl rand -hex 32)"

echo "📋 Шаг 3: Смена порта на 443 (защита от ТСПУ)..."
natbypass-cli config set network.preferred_port 443

echo "📋 Шаг 4: Перезапуск службы..."
natbypass-cli service restart

echo ""
echo "✅ Миграция завершена!"
echo ""
echo "📌 Следующие шаги:"
echo "1. Обновите все клиентские устройства до последней версии"
echo "2. Импортируйте новый конфиг: /etc/natbypass/awg31.conf"
echo "3. Проверьте подключение: natbypass-cli status"
echo ""
echo "🔍 Диагностика: natbypass-cli diag --awg"
