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