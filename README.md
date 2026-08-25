# NatBypass v1.2.7

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.2.7-8b5cf6?style=flat&logo=github)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
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

## ✨ Что нового в версии 1.2.7

- 🔐 **Мультипрофили сетей (Mesh Profiles)** — автоматическая генерация уникальных приватных топиков/ключей при первом запуске, создание нескольких сетей («Дом», «Офис», «Семья») с переключением на лету.
- 📱 **QR-код и шеринг профилей** — моментальный перенос настроек сети на смартфон или второй ПК через сканирование QR-кода или ссылку `natbypass://profile?...`.
- ⚡ **Честный замер задержки UDP-пинга** — удалены любые синтетические 14 мс; реальный динамический RTT и кнопка немедленного зондирования P2P-сокета.
- 🎨 **Зрелый минималистичный UI Android** — строгая контрастная темная палитра без «радужных» шрифтов и пестрых рамок в стиле Tailscale/WireGuard.
- 🌊 **Шелковистые графики (Cardinal Spline)** — плавная отрисовка трафика и задержки кубическими сплайнами Безье.
- 🪟 **Нативное окно Windows (Embedded WebView2)** — красивый современный UI прямо в процессе `NatBypass.exe` с поддержкой DPI Awareness, Dark Mode и системным треем.
- 📡 **4-уровневый стек отказоустойчивости** — `Direct P2P UDP ➔ AmneziaWG 2.0 ➔ MQTT Datagram Stream ➔ Xray Reality`.

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
| **Windows** | amd64 | [`NatBypass-v1.2.7-windows-amd64.exe`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Windows 10/11 (Desktop UI + Трей) |
| **Android** | arm64 / arm / x64 | [`NatBypass-v1.2.7.apk`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR-сканер) |
| **Linux** | amd64 | `natbypass-v1.2.7-linux-amd64` | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | `natbypass-v1.2.7-linux-arm64` | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **Роутеры MIPS** | mips (Big Endian) | `natbypass-v1.2.7-router-mips` | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **Роутеры MIPSLE** | mipsle (Little Endian)| `natbypass-v1.2.7-router-mipsle`| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Быстрая установка

### Windows
1. Скачайте [**`NatBypass-v1.2.7-windows-amd64.exe`**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
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
1. Скачайте [**`NatBypass-v1.2.7.apk`**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
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

