# 🐧 Инструкция по настройке для Linux (Ubuntu / Debian / CentOS / Arch)

На Linux серверах и рабочих станциях NatBypass работает как автономный фоновый демон с поддержкой `systemd`, Web UI и WireGuard.

---

## 1. Установка

```bash
# 1. Скачайте актуальный бинарник (x64 или ARM64)
sudo wget -O /usr/local/bin/natbypass https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-amd64
sudo chmod +x /usr/local/bin/natbypass

# 2. Создайте каталог конфигурации
sudo mkdir -p /etc/natbypass
sudo wget -O /etc/natbypass/config.yaml https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/config.yaml.example
```

---

## 2. Настройка `config.yaml`

Отредактируйте файл конфигурации:
```bash
sudo nano /etc/natbypass/config.yaml
```

Укажите данные вашего Telegram-бота или MQTT-топика:
```yaml
app:
  log_level: "info"
  publish_interval: 60

web_ui:
  enabled: true
  port: 8080

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

## 3. Запуск как Systemd служба

NatBypass имеет встроенную команду установки systemd-юнита:

```bash
# Автоматическая установка и регистрация службы
sudo natbypass install --service systemd

# Запуск и включение автозагрузки
sudo systemctl daemon-reload
sudo systemctl enable --now natbypass

# Проверка статуса и логов
sudo systemctl status natbypass
sudo journalctl -u natbypass -f
```

---

## 4. Подключение WireGuard на Linux

1. Установите WireGuard:
   ```bash
   sudo apt update && sudo apt install -y wireguard wireguard-tools
   ```
2. Получите готовую full-mesh конфигурацию через API демона:
   ```bash
   curl -s http://localhost:8080/api/wg/config | sudo tee /etc/wireguard/wg0.conf
   ```
3. Поднимите P2P интерфейс:
   ```bash
   sudo wg-quick up wg0
   sudo systemctl enable wg-quick@wg0
   ```
4. Проверьте статус туннеля:
   ```bash
   sudo wg show
   ping 10.200.0.1
   ```