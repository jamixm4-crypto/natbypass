# Межгеографическая P2P/DPI диагностика (natbypass-probe)

Утилита **`natbypass-probe`** создана для автоматического выявления блокировок UDP, фильтрации WireGuard-паттерна и проверки обхода ТСПУ/DPI между узлами в разных странах (РФ, РБ, США, Европа).

---

## 🚀 Быстрый запуск

### Linux x86_64:
```bash
curl -sSL -o natbypass-probe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe
./natbypass-probe --config probe.json --label "US / VPS" --country US --out report-us.json
```

### Windows (PowerShell):
```powershell
Invoke-WebRequest -Uri "https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-Probe.exe" -OutFile "natbypass-probe.exe"
.\natbypass-probe.exe --config probe.json --label "РФ / Home" --country RU --out report-ru.json
```

---

## 🔍 Что тестирует утилита:
1. **STUN и классификация NAT (RFC 5780)**: определяет тип NAT, симметричность и дельту портов.
2. **Фильтрация UDP провайдером**: отправка стандартных и обфусцированных UDP-проб.
3. **Обфускация AmneziaWG**: тестирование доставки пакетов с мусорным паддингом Jc/Jmin/Jmax и модифицированными заголовками H1..H4.
4. **Вывод отчёта**: JSON-файл с детальными метриками задержки, потерь и рекомендациями по настройке.
