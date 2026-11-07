# Удаление и сброс конфигурации NatBypass

Инструкция по полному удалению или очистке настроек NatBypass на Linux, роутерах Keenetic и OpenWrt.

---

## 🗑️ 1. Полное удаление программы со всеми файлами и ключами

Скрипт автоматически остановит службу, удалит исполняемые файлы, автозапуск, системные логи, профили и ключи WireGuard:

```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

Если вы хотите удалить программу, но **сохранить конфигурацию и ключи** для будущей переустановки:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
```

---

## 🔄 2. Очистка и сброс конфигурации (Без удаления программы)

Если вам нужно очистить настройки, сгенерировать новый DeviceID и чистую пару WireGuard-ключей без переустановки бинарника:

```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

---

## 💻 3. Ручное удаление или сброс (Офлайн)

### Роутеры Keenetic (Entware):
```bash
# Полное удаление:
/opt/etc/init.d/S99natbypass stop
rm -f /opt/etc/init.d/S99natbypass /opt/bin/natbypass /opt/usr/bin/natbypass
rm -rf /opt/etc/natbypass /opt/var/log/natbypass.log
killall natbypass 2>/dev/null || true

# Только сброс конфигурации:
/opt/etc/init.d/S99natbypass stop
rm -rf /opt/etc/natbypass/*
/opt/etc/init.d/S99natbypass start
```

### Linux-серверы (systemd):
```bash
# Полное удаление:
systemctl stop natbypass && systemctl disable natbypass
rm -f /etc/systemd/system/natbypass.service && systemctl daemon-reload
rm -f /usr/local/bin/natbypass /usr/bin/natbypass
rm -rf /etc/natbypass /var/log/natbypass.log
killall natbypass 2>/dev/null || true

# Только сброс конфигурации:
systemctl stop natbypass
rm -rf /etc/natbypass/*
systemctl start natbypass
```

### Роутеры OpenWrt:
```bash
# Полное удаление:
/etc/init.d/natbypass stop && /etc/init.d/natbypass disable
rm -f /etc/init.d/natbypass /usr/bin/natbypass
rm -rf /etc/natbypass
killall natbypass 2>/dev/null || true

# Только сброс конфигурации:
/etc/init.d/natbypass stop
rm -rf /etc/natbypass/*
/etc/init.d/natbypass start
```
