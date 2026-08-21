# 🌐 Инструкция по настройке для роутеров Keenetic (KN-xxxx)

Роутеры Keenetic поддерживают установку NatBypass через систему пакетов **Entware (OPKG)** на USB-накопитель или во встроенную память.

---

## 1. Определение архитектуры вашего Keenetic

| Модели Keenetic | Процессор | Архитектура для скачивания |
|---|---|---|
| **Ultra (KN-1810/1811), Giga (KN-1010/1011), Peak (KN-2710), Hero 4G+** | MediaTek MT7622 / MT7981 / ARM Cortex | **`natbypass-linux-arm64`** |
| **Start (KN-1110/1111), City, Air, Extra, Speedster, Omni, Hopper** | MediaTek MT7628 / MT7621 (MIPS 1004Kc) | **`natbypass-linux-mipsle`** |

---

## 2. Установка через Entware (OPKG)

Подключитесь к роутеру по SSH (`ssh root@192.168.1.1` порт `222`):

```bash
# 1. Создаем рабочую папку
mkdir -p /opt/etc/natbypass /opt/bin

# 2. Скачиваем бинарник (для MIPSLE роутеров Keenetic)
wget -O /opt/bin/natbypass https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-mipsle
chmod +x /opt/bin/natbypass

# (Для ARM64 моделей используйте natbypass-linux-arm64)

# 3. Скачиваем шаблон конфигурации
wget -O /opt/etc/natbypass/config.yaml https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/config.yaml.example
```

---

## 3. Настройка конфигурации `/opt/etc/natbypass/config.yaml`

```bash
nano /opt/etc/natbypass/config.yaml
```

Укажите данные Telegram или MQTT:
```yaml
app:
  name: "NatBypass-Keenetic"
  log_level: "info"
  publish_interval: 60

web_ui:
  enabled: true
  port: 8088 # Используем 8088 чтобы не конфликтовать со стандартным веб-интерфейсом Keenetic (80)

signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: true
      params:
        token: "ВАШ_ТОКЕН_БОТА"
        chat_id: "-100ВАШ_CHAT_ID"
```

---

## 4. Настройка автозапуска (Init Script `/opt/etc/init.d/S99natbypass`)

Создайте скрипт автозапуска:

```bash
cat << 'EOF' > /opt/etc/init.d/S99natbypass
#!/bin/sh

ENABLED=yes
PROCS=natbypass
ARGS="start --config /opt/etc/natbypass/config.yaml --log-file /opt/var/log/natbypass.log"
PREARGS=""
DESC=$PROCS
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

. /opt/etc/init.d/rc.func
EOF

chmod +x /opt/etc/init.d/S99natbypass
```

Запустите сервис:
```bash
/opt/etc/init.d/S99natbypass start
```

Проверьте статус:
* Логи: `cat /opt/var/log/natbypass.log`
* Веб-панель управления роутера: `http://192.168.1.1:8088`

---

## 5. Маршрутизация трафика через WireGuard на Keenetic

В веб-интерфейсе Keenetic (*Сетевые правила -> WireGuard*):
1. Добавьте подключение WireGuard.
2. Вставьте сгенерированный NatBypass публичный/приватный ключ и адрес `10.200.0.1/24`.
3. Добавьте пиры ваших остальных устройств.
4. Теперь вся домашняя локальная сеть за роутером может безопасно общаться с вашими удаленными ПК и телефонами через P2P!