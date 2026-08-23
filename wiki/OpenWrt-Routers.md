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