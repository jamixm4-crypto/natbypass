# 📡 Установка NatBypass на роутеры OpenWrt

NatBypass совместим с роутерами на базе **OpenWrt** (архитектуры MIPS, MIPSLE, ARM, ARM64, x86).

---

## ⚡ Быстрая установка через SSH

1. Подключитесь к роутеру по SSH (`ssh root@192.168.1.1`).
2. Убедитесь, что установлены пакеты `curl` и `kmod-tun`:
   ```sh
   opkg update && opkg install curl kmod-tun ca-bundle
   ```
3. Запустите автоматический установщик:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
   ```

Скрипт установит службу `procd` (`/etc/init.d/natbypass`) и включит автозапуск при включении роутера.

---

## ⚙️ Веб-панель и настройка зоны Firewall
Панель управления доступна по адресу `http://192.168.1.1:8080`.

Для свободного доступа ко всей домашней сети через роутер:
1. В веб-интерфейсе OpenWrt (LuCI) перейдите в **Сеть ➔ Брандмауэр**.
2. Добавьте интерфейс `natbypass` (или `tun0`) в зону **LAN**.

---

## 🗑️ Полное удаление NatBypass с OpenWrt

### Способ 1: Автоматическое удаление через скрипт
```sh
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

Если вы хотите удалить бинарники, но **сохранить конфигурацию и ключи**:
```sh
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
```

### Способ 2: Ручное удаление через SSH
```sh
# 1. Остановить и отключить службу procd
/etc/init.d/natbypass stop
/etc/init.d/natbypass disable

# 2. Удалить скрипт службы и бинарник
rm -f /etc/init.d/natbypass /usr/bin/natbypass /usr/local/bin/natbypass

# 3. Удалить директорию конфигурации и логов
rm -rf /etc/natbypass /var/log/natbypass.log /var/run/natbypass.pid

# 4. Завершить процесс
killall natbypass 2>/dev/null || true
```

---

## 🧹 Очистка и сброс конфигурации (Без удаления программы)

### Способ 1: В 1 команду через скрипт
```sh
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

### Способ 2: Вручную через SSH
```sh
# 1. Остановить службу
/etc/init.d/natbypass stop

# 2. Очистить конфигурацию
rm -rf /etc/natbypass/*

# 3. Запустить службу (создастся чистая конфигурация)
/etc/init.d/natbypass start
```