# 📡 Инструкция по настройке для роутеров OpenWrt

NatBypass идеально подходит для роутеров под управлением OpenWrt (Xiaomi, TP-Link, MikroTik, GL.iNet, Banana Pi и др.).

---

## 1. Определение архитектуры

* Большинство роутеров на чипах MediaTek MT7621 / MT7628 / Atheros: **`natbypass-linux-mipsle`**
* Роутеры на чипах Atheros AR71xx / AR934x: **`natbypass-linux-mips`** (Big Endian)
* Роутеры на чипах MediaTek Filogic (MT7981 / MT7986), Rockchip RK3328/RK3568, Raspberry Pi: **`natbypass-linux-arm64`**
* x86/x64 роутеры и виртуалки: **`natbypass-linux-amd64`**

---

## 2. Установка на OpenWrt

Подключитесь к роутеру по SSH (`ssh root@192.168.1.1`):

```bash
# 1. Скачиваем бинарник в /usr/bin/
wget -O /usr/bin/natbypass https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-mipsle
chmod +x /usr/bin/natbypass

# 2. Создаем директорию для настроек
mkdir -p /etc/natbypass
wget -O /etc/natbypass/config.yaml https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/config.yaml.example
```

---

## 3. Настройка Procd службы автозапуска (`/etc/init.d/natbypass`)

Создайте системный сервис OpenWrt:

```bash
cat << 'EOF' > /etc/init.d/natbypass
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=10

PROG=/usr/bin/natbypass
CONF=/etc/natbypass/config.yaml

start_service() {
    procd_open_instance
    procd_set_param command $PROG start --config $CONF
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF

chmod +x /etc/init.d/natbypass
```

Включите службу и запустите её:
```bash
/etc/init.d/natbypass enable
/etc/init.d/natbypass start
```

Проверьте статус службы:
```bash
logread -e natbypass
```