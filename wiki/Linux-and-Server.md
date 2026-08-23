# 🐧 Руководство для Linux и Серверов

NatBypass на Linux работает как легковесный демон без графической оболочки (headless daemon) с поддержкой веб-панели управления.

---

## ⚡ Установка в 1 команду

Выполните на сервере (Ubuntu, Debian, CentOS, Arch):

```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(или через `wget`: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Скрипт автоматически:
* Определит архитектуру процессора (`x86_64` или `ARM64`).
* Создаст системную службу `systemd` (`natbypass.service`).
* Запустит Web-интерфейс на порту `8080`.

---

## 🌐 Управление через Веб-панель
Откройте браузер: `http://<IP_СЕРВЕРА>:8080`.
В панели доступны:
* Мониторинг подключенных пиров и задержки в реальном времени.
* Настройка Telegram и MQTT каналов.
* Генерация конфигураций WireGuard и AmneziaWG 2.0.

---

## 🛠️ Управление службой через systemctl
```bash
# Статус службы
systemctl status natbypass

# Перезапуск
systemctl restart natbypass

# Остановка
systemctl stop natbypass

# Логи в реальном времени
journalctl -u natbypass -f
```

---

## 🔄 Обновление
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/update.sh | sh
```