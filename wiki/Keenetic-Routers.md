# 🌐 Установка NatBypass на роутеры Keenetic

NatBypass работает на роутерах Keenetic с установленной средой **Entware** (на USB-накопителе или встроенной памяти).

---

## ⚡ Установка в 1 команду через SSH

1. Подключитесь к роутеру по SSH (`ssh root@192.168.1.1`, порт `222` для Entware).
2. Выполните команду автоматической установки:

```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(или через `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Скрипт сам:
* Определит архитектуру процессора (`MIPS`, `MIPSLE` или `ARM64`).
* Скачает актуальный релиз.
* Установит службу `/opt/etc/init.d/S99natbypass`.
* Запустит Web-интерфейс на порту `8080`.

---

## Настройка через Web-интерфейс
Откройте в браузере: `http://192.168.1.1:8080` и настройте параметры сигнального канала (Telegram / MQTT).

---

## 🔄 Обновление
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/update.sh | sh
```
Конфигурация, токены и ключи сохраняются полностью.

---

## 🗑️ Полное удаление NatBypass с Keenetic

### Способ 1: Автоматическое удаление через скрипт
Удаление всех бинарников, службы автозапуска и файлов конфигурации:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

Если вы хотите удалить программу, но **сохранить текущие настройки и ключи**:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
```

### Способ 2: Ручное удаление через SSH
Выполните поочередно команды в консоли Entware:
```bash
# 1. Остановить службу
/opt/etc/init.d/S99natbypass stop

# 2. Удалить скрипт автозапуска и исполняемый файл
rm -f /opt/etc/init.d/S99natbypass
rm -f /opt/bin/natbypass /opt/usr/bin/natbypass /opt/sbin/natbypass

# 3. Удалить директорию с конфигурацией и ключами
rm -rf /opt/etc/natbypass /opt/var/log/natbypass.log /opt/var/run/natbypass.pid

# 4. Завершить оставшиеся процессы (если есть)
killall natbypass 2>/dev/null || true
```

---

## 🧹 Очистка и сброс конфигурации (Без удаления программы)

Если нужно сбросить настройки, сгенерировать новый DeviceID и чистые ключи WireGuard, оставив саму программу установленной:

### Способ 1: В 1 команду через скрипт
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

### Способ 2: Вручную через SSH
```bash
# 1. Остановить службу
/opt/etc/init.d/S99natbypass stop

# 2. Очистить файлы конфигурации
rm -rf /opt/etc/natbypass/*

# 3. Запустить службу (создаст чистый config.yaml и новые ключи)
/opt/etc/init.d/S99natbypass start
```