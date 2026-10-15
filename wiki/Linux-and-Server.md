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

---

## 🗑️ Полное удаление NatBypass с Linux

### Способ 1: Автоматическое удаление через скрипт
Удаление всех бинарников, службы systemd, логов и файлов конфигурации:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

Если нужно удалить программу, но **сохранить конфигурацию и ключи**:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
```

### Способ 2: Ручное удаление
```bash
# 1. Остановить и отключить службу systemd
sudo systemctl stop natbypass
sudo systemctl disable natbypass

# 2. Удалить юнит службы
sudo rm -f /etc/systemd/system/natbypass.service
sudo systemctl daemon-reload

# 3. Удалить исполняемые файлы
sudo rm -f /usr/local/bin/natbypass /usr/bin/natbypass /usr/local/sbin/natbypass

# 4. Удалить конфигурацию и логи
sudo rm -rf /etc/natbypass /var/log/natbypass.log /var/run/natbypass.pid

# 5. Завершить оставшиеся процессы
sudo killall natbypass 2>/dev/null || true
```

---

## 🧹 Очистка и сброс конфигурации (Без удаления программы)

Если вам нужно сбросить конфигурацию к заводским настройкам, создать новый DeviceID и перегенерировать ключи:

### Способ 1: В 1 команду через скрипт
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

### Способ 2: Вручную
```bash
# 1. Остановить службу
sudo systemctl stop natbypass

# 2. Очистить файлы конфигурации
sudo rm -rf /etc/natbypass/*

# 3. Запустить службу (автоматически создастся чистый config.yaml и новые ключи)
sudo systemctl start natbypass
```