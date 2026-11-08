# 🔧 Диагностика и Troubleshooting

Если устройства не видят друг друга или пинг не проходит, воспользуйтесь встроенной системой диагностики.

---

## 1. Встроенная диагностика в Web UI
Перейдите на вкладку **«⚙ Настройки» ➔ «Диагностика»** и нажмите **«Запустить проверку»**.

Система выполнит:
* **Проверку доступа к Интернету:** доступность публичных DNS-серверов.
* **Определение внешнего IP и STUN:** опрос серверов `stun.l.google.com` и `stun.cloudflare.com`.
* **Определение типа NAT:**
  * `Full Cone / Restricted Cone NAT` — прямое P2P соединение устанавливается мгновенно.
  * `Symmetric NAT` — задействуется согласованное пробитие портов или предсказание портов.
* **Проверку сигнального канала:** статус доставки маяков через MQTT или Telegram.

---

## 2. Экспресс-диагностика в одну команду

* **Linux / Keenetic / OpenWrt:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh
  ```
* **Windows (PowerShell):**
  ```powershell
  irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex
  ```

---

## 3. Межсетевая утилита тестирования (NatBypass-Probe)
Для детального замера потерь, джиттера и устойчивости к ТСПУ/DPI между удалёнными узлами используйте [NatBypass-Probe](Probe-Diagnostics):
* **Windows:** `.\NatBypass-Probe.exe --config probe.json`
* **Linux:** `./natbypass-probe-linux-amd64 --config probe.json`
