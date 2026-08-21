<div align="center">

# 🛸 NatBypass

**Кроссплатформенное приложение для обхода NAT (включая двойной NAT / CGNAT) и организации прямого зашифрованного P2P Mesh-доступа между всеми вашими устройствами.**

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

## 📚 Подробные инструкции по настройке клиентов

Подробные пошаговые руководства с примерами конфигураций для каждой платформы:

| Платформа | Документация | Особенности |
|---|---|---|
| 🪟 **Windows** | [**Инструкция для Windows (docs/WINDOWS.md)**](docs/WINDOWS.md) | Desktop GUI, System Tray, служба Windows Service, WireGuard клиент |
| 🐧 **Linux** | [**Инструкция для Linux (docs/LINUX.md)**](docs/LINUX.md) | Автоматический Systemd сервис, headless демон, автозапуск |
| 🌐 **Keenetic** | [**Инструкция для Keenetic (docs/ROUTERS_KEENETIC.md)**](docs/ROUTERS_KEENETIC.md) | Установка через Entware/OPKG, автозапуск `init.d`, модели MIPS/ARM64 |
| 📡 **OpenWrt** | [**Инструкция для OpenWrt (docs/ROUTERS_OPENWRT.md)**](docs/ROUTERS_OPENWRT.md) | Служба `procd`, интеграция в систему, минимальное потребление RAM |
| 📱 **Android** | [**Инструкция для Android (docs/ANDROID.md)**](docs/ANDROID.md) | Запуск через Termux, мобильный Web UI, WireGuard Android App |
| 💬 **Сигнализация** | [**Настройка Telegram / MQTT / DNS (docs/SIGNALING_SETUP.md)**](docs/SIGNALING_SETUP.md) | Пошаговое создание бота, настройка брокеров и топиков |
| 🔒 **WireGuard** | [**Принцип работы Mesh-сети (docs/WIREGUARD_MESH.md)**](docs/WIREGUARD_MESH.md) | UDP Hole Punching, адресация подсети `10.200.0.0/24` |

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

## 💻 Поддерживаемые платформы и бинарники

| Платформа | Архитектура | Целевые устройства | Готовый файл |
|---|---|---|---|
| **Windows** | `amd64` | Windows 10/11, Server (GUI + Tray + Service) | `natbypass-windows-amd64.exe` / `NatBypass.exe` |
| **Linux** | `amd64` | Ubuntu, Debian, CentOS, Arch | `natbypass-linux-amd64` |
| **Linux ARM64** | `arm64` | Keenetic Ultra/Giga/Peak, Raspberry Pi 3/4/5 | `natbypass-linux-arm64` |
| **Linux MIPS** | `mips` *(Big Endian)* | Роутеры OpenWrt, Mikrotik MIPSBE | `natbypass-linux-mips` |
| **Linux MIPSLE** | `mipsle` *(Little Endian)* | Keenetic Start/City/Air, Xiaomi 3G/4A | `natbypass-linux-mipsle` |
| **Android** | `arm64` | Смартфоны (Termux / ADB / AAR / APK) | `natbypass-android-arm64` |
| **macOS / iOS** | `arm64` | Apple Silicon Mac, iPhone (Framework) | `natbypass-darwin-arm64` |

---

## 🚀 Быстрый старт за 3 шага

### 1. Подготовка конфигурации (`config.yaml`)
Скопируйте `config.yaml.example` в `config.yaml` и укажите данные вашего Telegram-бота (или MQTT):
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
        token: "7123456789:AAFlkjhsdf..."
        chat_id: "-1001234567890"
    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "tcp://mqtt.eclipseprojects.io:1883"
        topic: "natbypass/secret-mesh/peers"
```

### 2. Запуск
* **На Windows:** Дважды кликните по **`NatBypass.exe`** (программа появится в трее и откроет окно панели управления).
* **На Linux / Роутере:** Выполните `./natbypass start --config config.yaml`.

### 3. Проверка подключения
Откройте браузер по адресу **`http://localhost:8080`** — вы увидите список всех обнаруженных узлов сети, их реальные внешние сокеты и сможете в один клик сгенерировать WireGuard-конфиг для защищенного P2P соединения!

---

## 🔨 Сборка собственных пакетов (Builder)

Для встраивания параметров Telegram/MQTT и компиляции под ваши устройства предусмотрено 2 удобных способа:

### Вариант А: Через графический сборщик (NatBypass Builder GUI)
1. Скачайте архив **`NatBypass-Builder-Toolkit-windows.zip`** со страницы [Releases](../../releases) (либо скачайте исходники через `git clone https://github.com/jamixm4-crypto/natbypass.git`).
2. Распакуйте архив и запустите **`NatBypass-Builder.exe`**.
3. Заполните токены Telegram / MQTT, выберите целевые платформы галочками и нажмите **«🔨 Начать сборку»**.
4. Сборщик автоматически скомпилирует готовые бинарники в папку `dist\`.

> [!NOTE]
> Графический сборщик `NatBypass-Builder.exe` компилирует код локально на вашей машине, поэтому для его работы необходимы файлы исходного кода проекта (`cmd/`, `internal/`, `go.mod`), которые уже включены в архив **`NatBypass-Builder-Toolkit-windows.zip`**.

### Вариант Б: Через Makefile (Консоль / Linux / CI)
```bash
make all            # Сборка под все платформы
make windows-amd64  # Сборка под Windows (.exe)
make linux-cli      # Сборка под Linux x64
make router-mipsle  # Сборка под Keenetic (MIPSLE)
make router-arm64   # Сборка под ARM64
make android-arm64  # Сборка под Android
make android-apk    # Сборка APK пакета
```

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