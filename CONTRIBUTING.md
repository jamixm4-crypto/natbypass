# Руководство по участию в разработке NatBypass (Contributing)

Мы приветствуем вклад сообщества в развитие проекта NatBypass!

## Структура репозитория

* `cmd/natbypass-cli/` — CLI-клиент и демон для серверов, роутеров и встраиваемых систем.
* `cmd/natbypass-gui/` — Windows GUI приложение на базе Wails v2 и системного трея.
* `cmd/builder/` — Нативный графический кроссплатформенный компилятор для Windows.
* `internal/crypto/` — Криптография NaCl/Box (X25519, XSalsa20-Poly1305).
* `internal/network/` — STUN клиент (RFC 5389), UPnP/IGD и fallback определение IP.
* `internal/signaling/` — Сигнальные каналы (Telegram Bot API, MQTT, Webhook, Cloudflare DNS) и FallbackManager.
* `internal/peer/` — Потокобезопасный реестр пиров P2P сети.
* `internal/wireguard/` — Генератор Full-Mesh конфигураций WireGuard в чистом Go (0 CGO).
* `internal/webui/` — Встроенный легковесный веб-сервер и панель управления.
* `pkg/mobile/` — JNI мост для Android / iOS (Gomobile).

## Требования к разработке

1. **Go 1.22+**: Все компоненты для embedded-систем и роутеров должны компилироваться с `CGO_ENABLED=0`.
2. **Чистота кода**: Перед отправкой PR выполните:
   ```bash
   go vet ./...
   go test ./...
   ```
3. **Безопасность**: Никогда не коммитьте реальные токены ботов, пароли и приватные ключи в Git.