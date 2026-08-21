<div align="center">

# 🛸 NatBypass

**Кроссплатформенное приложение для обхода NAT (включая двойной NAT / CGNAT) и организации прямого P2P Mesh-доступа между устройствами.**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20MIPS%20%7C%20ARM64%20%7C%20Android-brightgreen)](#-поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)
[![Security](https://img.shields.io/badge/Crypto-NaCl%20%2F%20X25519-red)](internal/crypto)

</div>

---

## 🌟 Ключевые возможности

* **Обход сложного NAT и CGNAT (RFC 5389 STUN):** Автоматическое определение внешних сокетов `IP:Port` через независимые STUN-серверы и UPnP/NAT-PMP.
* **Мультиканальная сеть сигнализации (Signaling Mesh):**
  * 💬 **Telegram Bot API:** Обмен через защищенные сообщения в приватном канале (работает через SOCKS5/HTTP прокси).
  * ⚡ **MQTT Broker:** Легковесный publish/subscribe с гарантией QoS 1 и автопереподключением.
  * 🔗 **HTTP Webhook:** Защищенные POST-запросы с HMAC-SHA256 подписью.
  * 🌍 **Cloudflare DNS:** Передача состояния через DNS TXT записи и DNS-over-HTTPS (DoH).
* **Отказоустойчивый Fallback Manager:** Автоматическое переключение сигнальных каналов с экспоненциальной задержкой (Exponential Backoff) и Circuit Breaker при сбоях.
* **End-to-End шифрование (E2EE):** Полное шифрование всех пакетов сигнализации алгоритмом **NaCl/Box** (Curve25519 + XSalsa20-Poly1305).
* **Автоматический WireGuard Full-Mesh:** Генерация совместимых конфигураций WireGuard (`wg0.conf`) на чистом Go (без CGO) для прямого туннелирования.
* **Графические интерфейсы (GUI):**
  * 🪟 **Desktop GUI (Wails / Win32):** Нативное десктопное окно со статусом сети, таблицей пиров, логами и системным треем.
  * 🌐 **Встроенный Web UI:** Легковесный веб-интерфейс (`http://localhost:8080`) с автоперебором портов при конфликтах.
  * 🔨 **Нативный Сборщик (Builder GUI):** Автономное Win32-приложение для сборки бинарников под все платформы в один клик.
* **Системные службы:** Управление службой Windows (`sc.exe` / `golang.org/x/sys/windows/svc`) и демонизация на Linux (`systemd`, OpenWrt `procd`, Entware).
* **Поддержка роутеров и мобильных ОС:** 100% статическая сборка без libc для Keenetic, OpenWrt, Mikrotik, Raspberry Pi, Android и iOS.

---

## 📐 Архитектура системы

```
                ┌─────────────────────────────────────────────────────────┐
                │          Мультиканальная сеть сигнализации             │
                │  [Telegram Bot] ── [MQTT Broker] ── [DoH DNS] ── [HTTP] │
                └───────────▲─────────────────────────────────▲───────────┘
                            │ (End-to-End Encrypted Payload)  │
                            │                                 │
           ┌────────────────┴───────────────┐     ┌───────────┴────────────────┐
           │     Устройство A (Клиент)      │     │    Устройство B (Сервер)   │
           │  • RFC 5389 STUN Discovery    │     │  • RFC 5389 STUN Discovery │
           │  • NaCl/Box KeyPair            │     │  • NaCl/Box KeyPair        │
           │  • Peer Registry Monitor       │     │  • Peer Registry Monitor   │
           │  • Embedded Web UI (Port 8080) │     │  • Embedded Web UI         │
           └────────────────┬───────────────┘     └───────────┬────────────────┘
                            │                                 │
                            └─────── Direct WireGuard P2P ────┘
                                     (Tunnel: 10.200.0.0/24)
```

---

## 💻 Поддерживаемые платформы

| Платформа | Архитектура | Целевые устройства | Статус |
|---|---|---|---|
| **Windows** | `amd64` | Windows 10/11, Server (GUI + Tray + Service) | ✅ Поддерживается |
| **Linux** | `amd64` | Ubuntu, Debian, CentOS, Arch | ✅ Поддерживается |
| **Linux ARM64** | `arm64` | Keenetic Ultra/Giga/Peak, Raspberry Pi 3/4/5 | ✅ Поддерживается |
| **Linux MIPS** | `mips` *(Big Endian)* | Роутеры OpenWrt, Mikrotik MIPSBE | ✅ Поддерживается |
| **Linux MIPSLE** | `mipsle` *(Little Endian)* | Keenetic Start/City/Air, Xiaomi 3G/4A | ✅ Поддерживается |
| **Android** | `arm64` | Смартфоны (Termux / ADB / AAR / APK) | ✅ Поддерживается |
| **macOS / iOS** | `arm64` | Apple Silicon Mac, iPhone (Framework) | ✅ Поддерживается |

---

## 🚀 Быстрый старт

### 1. Windows:
1. Скачайте архив из [Releases](../../releases) или соберите проект.
2. Скопируйте `config.yaml.example` в `config.yaml` и укажите данные Telegram / MQTT:
   ```yaml
   signaling:
     channels:
       - type: "telegram"
         enabled: true
         params:
           token: "ВАШ_ТОКЕН_БОТА"
           chat_id: "ВАШ_CHAT_ID"
   ```
3. Запустите **`NatBypass.exe`** — программа свернется в трей и откроет панель управления.

### 2. Linux / Роутеры (Keenetic / OpenWrt):
```bash
# 1. Скачайте бинарник под вашу архитектуру
wget https://github.com/natbypass/natbypass/releases/latest/download/natbypass-linux-mipsle
chmod +x natbypass-linux-mipsle

# 2. Создайте конфигурацию
cp config.yaml.example config.yaml

# 3. Запустите приложение в фоновом режиме
./natbypass-linux-mipsle start --config config.yaml
```

---

## 🔨 Сборка из исходников

### Сборка через Makefile:
```bash
# Сборка под все платформы
make all

# Сборка отдельных целевых платформ
make windows-amd64   # Windows x64 (.exe)
make linux-cli       # Linux x64
make router-mips     # MIPS Big Endian
make router-mipsle   # MIPSLE Little Endian (Keenetic)
make router-arm64    # ARM64
make android-arm64   # Android ARM64
make android-apk     # Android APK пакет
make windows-gui     # Wails GUI
```

### Сборка через графический интерфейс (Builder GUI):
На Windows запустите **`NatBypass-Builder.exe`**, укажите параметры Telegram/MQTT и нажмите **«🔨 Начать сборку»**.

---

## 📜 Команды CLI

```text
NatBypass — P2P NAT Traversal Tool

Использование:
  natbypass [команда] [флаги]

Доступные команды:
  start          Запуск фонового демона (основной рабочий цикл)
  status         Текущее состояние сети, пиров и внешний IP
  stop           Корректная остановка демона по PID
  keygen         Генерация пары ключей шифрования NaCl/Box (X25519)
  wg keygen      Генерация ключей WireGuard
  wg config      Генерация конфигурационного файла wg0.conf
  service        Управление системной службой Windows (install|uninstall|start|stop)
  install        Установка сервиса на Linux (systemd|procd|entware)
  version        Показать версию и дату сборки
```

---

## 📄 Лицензия

Проект распространяется под свободной лицензией [MIT](LICENSE).