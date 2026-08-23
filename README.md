# NatBypass v1.2.4

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.2.4-8b5cf6?style=flat&logo=github)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](wiki/Home.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

## 📚 [Официальная База Знаний (Wiki)](wiki/Home.md)

Полная документация и пошаговые инструкции доступны в нашей [**NatBypass Wiki**](wiki/Home.md):
* 🚀 [**Быстрый старт за 5 минут**](wiki/Quick-Start.md) — подключение первой P2P-пары устройств без консоли.
* 🛡️ [**Обход блокировок (AmneziaWG 2.0)**](wiki/AmneziaWG-DPI-Bypass.md) — тюнинг параметров $J_c, S_1, S_2, H_1..H_4$ против ТСПУ / DPI.
* 🌐 [**Роутеры Keenetic (Entware)**](wiki/Keenetic-Routers.md) & [**OpenWrt**](wiki/OpenWrt-Routers.md) — установка в 1 команду и автозапуск.
* 📱 [**Android-руководство**](wiki/Android-Setup.md) — подключение по QR-коду и системный VpnService.
* 🔧 [**Диагностика и устранение неполадок**](wiki/Troubleshooting-and-Diagnostics.md) — расшифровка NAT-типов и проверка связности.

---

## ✨ Что нового в версии 1.2.4

- 🌊 **Шелковистые неоновые графики (Cardinal Spline)** — плавная отрисовка трафика и задержки кубическими сплайнами Безье с динамической неоновой подсветкой.
- ⚡ **EMA-сглаживание пинга** — экспоненциальное скользящее среднее устраняет сетевой джиттер и предотвращает скачки RTT.
- 🪟 **Нативное окно Windows (Embedded WebView2)** — красивый современный UI прямо в процессе `NatBypass.exe` с поддержкой Dark Mode, системным треем и защитой от дублирования окон.
- 📱 **Полноценный GoMobile AAR для Android** — нативный P2P Go-движок внутри `NatBypass.apk` с поддержкой сканирования QR-кодов, AmneziaWG 2.0 и виджетом в шторке.
- 📡 **4-уровневый стек отказоустойчивости** — автоматический переход: `Direct P2P UDP ➔ AmneziaWG 2.0 ➔ MQTT Datagram Stream ➔ Xray VLESS Reality (TCP 443)`.
- 🔒 **Шифрование настроек DPAPI** — учетные данные и приватные ключи защищены криптографией Windows Data Protection.

---

## 🏗️ Архитектура P2P сети

```
              ┌──────────────────────────────────────────────┐
              │          Каналы сигнализации                 │
              │     [Telegram Bot]  ──  [MQTT Broker]        │
              └────────▲─────────────────────────▲──────────┘
                       │  (зашифрованные маяки)  │
                       │                         │
         ┌─────────────┴──────────┐   ┌──────────┴─────────────┐
         │    Устройство A        │   │    Устройство B        │
         │  STUN Discovery        │   │  STUN Discovery        │
         │  Windows App (Wintun)  │   │  Keenetic / Linux / Android
         │  IP: 10.200.0.1        │   │  IP: 10.200.0.2        │
         └─────────────┬──────────┘   └──────────┬─────────────┘
                       │                         │
                       └──── Direct UDP Socket ──┘
                              (P2P / AWG 2.0)
```

Устройства обмениваются зашифрованными маяками через Telegram или MQTT. Когда внешние сокеты определены через STUN, открывается прямой P2P UDP-туннель. Серверы-посредники для самого трафика **не используются**.

---

## 📦 Поддерживаемые платформы

| Платформа | Архитектура | Файл релиза | Описание |
|---|---|---|---|
| **Windows** | amd64 | [`NatBypass-v1.2.4-windows-amd64.exe`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Windows 10/11 (Desktop UI + Трей) |
| **Android** | arm64 / arm / x64 | [`NatBypass-v1.2.4.apk`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR-сканер) |
| **Linux** | amd64 | `natbypass-v1.2.4-linux-amd64` | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | `natbypass-v1.2.4-linux-arm64` | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **Роутеры MIPS** | mips (Big Endian) | `natbypass-v1.2.4-router-mips` | OpenWrt, MikroTik |
| **Роутеры MIPSLE** | mipsle (Little Endian)| `natbypass-v1.2.4-router-mipsle`| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Быстрая установка

### Windows
1. Скачайте [**`NatBypass-v1.2.4-windows-amd64.exe`**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. Запустите от имени администратора.
3. В разделе **«Настройки»** укажите данные Telegram-бота или MQTT-брокера и нажмите **«💾 Сохранить»**.

### Linux / Keenetic / OpenWrt (Установка в 1 команду)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(или через `wget`: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Панель управления будет доступна по адресу: `http://<IP_УСТРОЙСТВА>:8080`.

#### 🔄 Обновление в 1 команду (сохраняет все настройки)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/update.sh | sh
```

#### 🗑️ Удаление
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh
```

### Android
1. Скачайте [**`NatBypass-v1.2.4.apk`**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. Нажмите **«📷 Сканировать QR»** и наведите камеру на QR-код во вкладке *«Быстрый старт»* на ПК для мгновенного импорта настроек!

---

## 🛠️ Сборка из исходников

```bash
# Windows Desktop App (с нативным WebView2)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o NatBypass.exe ./cmd/natbypass

# Linux / Сервер
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o natbypass ./cmd/natbypass

# MIPSLE для роутеров Keenetic / OpenWrt
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags="-s -w" -o natbypass-mipsle ./cmd/natbypass
```

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).

