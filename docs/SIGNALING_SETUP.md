# 📡 Настройка сигнальных каналов (Signaling Channels)

Сигнальная сеть используется для первоначального обнаружения узлов, обмена публичными ключами **NaCl/Box** (X25519) и динамическими адресами **STUN Endpoint** (`IP:Port`). Сам пользовательский трафик через сигнальные каналы **не идет** — он идет напрямую через зашифрованный WireGuard туннель.

---

## 1. 💬 Telegram Bot API (Рекомендуемый канал)

Самый стабильный и простой в настройке канал. Работает даже за жесткими файрволами и мобильными операторами.

### Шаг 1: Создание бота
1. Откройте Telegram и найдите бота [@BotFather](https://t.me/BotFather).
2. Отправьте команду `/newbot`.
3. Задайте имя (например, `MyNatBypassBot`) и юзернейм (например, `my_natbypass_123_bot`).
4. Скопируйте полученный **HTTP API Token** (вида `7123456789:AAFlkjhsdf...`).

### Шаг 2: Создание приватной группы/канала
1. В Telegram создайте **Новую группу** или **Приватный канал** (например, `NatBypass Network`).
2. Добавьте созданного бота в группу/канал как **Администратора** с правами отправки сообщений.
3. Отправьте любое тестовое сообщение в эту группу.

### Шаг 3: Получение Chat ID
1. Перейдите по ссылке в браузере (подставив ваш токен):
   `https://api.telegram.org/bot<ВАШ_ТОКЕН>/getUpdates`
2. Найдите в JSON-ответе поле `"chat":{"id": -100xxxxxxxxxx}`.
3. Скопируйте этот `chat_id` (обычно начинается с `-100` для супергрупп/каналов).

### Шаг 4: Конфигурация в `config.yaml`
```yaml
signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: true
      params:
        token: "7123456789:AAFlkjhsdf..."
        chat_id: "-1001234567890"
        proxy: "" # Опционально: socks5://127.0.0.1:1080 при блокировках
```

---

## 2. ⚡ MQTT Broker (Быстрый P2P обмен с минимальным пингом)

MQTT обеспечивает мгновенный обмен пирами в реальном времени с минимальным потреблением трафика (< 1 КБ на узел).

### Бесплатные публичные брокеры (для быстрого старта):
* `tcp://mqtt.eclipseprojects.io:1883`
* `tcp://broker.hivemq.com:1883`
* `tcp://broker.emqx.io:1883`

### Конфигурация в `config.yaml`:
```yaml
signaling:
  channels:
    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "tcp://mqtt.eclipseprojects.io:1883"
        topic: "natbypass/secret-uuid-mesh/peers" # Придумайте уникальный случайный топик
        username: "" # Если брокер требует авторизации
        password: ""
```

---

## 3. 🌍 Cloudflare DNS TXT (Ультра-скрытный канал)

Передает состояние сети через DNS TXT записи через Cloudflare DNS-over-HTTPS (DoH). Блокировка невозможна без отключения HTTPS.

1. Зарегистрируйте бесплатный домен на Cloudflare.
2. В панели Cloudflare перейдите в **My Profile -> API Tokens -> Create Token** (шаблон: *Edit zone DNS*).
3. Скопируйте **API Token** и **Zone ID** домена.
4. Конфигурация в `config.yaml`:
```yaml
signaling:
  channels:
    - type: "dns"
      priority: 3
      enabled: true
      params:
        cf_api_token: "ВАШ_CLOUDFLARE_API_TOKEN"
        zone_id: "ВАШ_ZONE_ID"
        record_name: "peers.yourdomain.com"
```

---

## 4. 🔗 HTTP Webhook (Собственный сервер)

Для корпоративных сетей или собственного VPS сервера:

```yaml
signaling:
  channels:
    - type: "webhook"
      priority: 4
      enabled: true
      params:
        post_url: "https://your-server.com/api/natbypass/publish"
        poll_url: "https://your-server.com/api/natbypass/poll"
        secret: "super-secret-hmac-key-256"
```