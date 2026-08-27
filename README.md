# NatBypass v1.5.2

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.5.2-8b5cf6?style=flat&logo=github)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

## 📚 [Официальная База Знаний (Wiki)](https://github.com/jamixm4-crypto/natbypass/wiki)

Полная документация и пошаговые инструкции доступны в нашей [**NatBypass Wiki**](https://github.com/jamixm4-crypto/natbypass/wiki):
* 🚀 [**Быстрый старт за 5 минут**](https://github.com/jamixm4-crypto/natbypass/wiki/Quick-Start) — подключение первой P2P-пары устройств без консоли.
* 🛡️ [**Обход блокировок (AmneziaWG 2.0)**](https://github.com/jamixm4-crypto/natbypass/wiki/AmneziaWG-DPI-Bypass) — тюнинг параметров $J_c, S_1, S_2, H_1..H_4$ против ТСПУ / DPI.
* 🌐 [**Роутеры Keenetic (Entware)**](https://github.com/jamixm4-crypto/natbypass/wiki/Keenetic-Routers) & [**OpenWrt**](https://github.com/jamixm4-crypto/natbypass/wiki/OpenWrt-Routers) — установка в 1 команду и автозапуск.
* 📱 [**Android-руководство**](https://github.com/jamixm4-crypto/natbypass/wiki/Android-Setup) — подключение по QR-коду, отображение QR на экране и системный VpnService.
* 🪟 [**Windows-руководство**](https://github.com/jamixm4-crypto/natbypass/wiki/Windows-Guide) — нативный UI, трей, Wintun и серверный режим.
* 🔧 [**Диагностика и устранение неполадок**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — расшифровка NAT-типов и проверка связности.

---

## ✨ Что нового в версии 1.5.2

- 📱 **Интерактивный экранный QR-код в Android** — удобный просмотр и копирование QR-кода активной конфигурации прямо на экране смартфона для сканирования другими устройствами.
- ⚡ **Мгновенное сопряжение устройств** — QR-код приглашения в Web UI и на мобильном теперь сразу передаёт полный профиль сети (`natbypass://profile?...`) и инициирует немедленный опрос STUN и отправку маяка.
- 🛡️ **Защита от сброса задач Android при отключении VPN** — внедрена передача дескриптора через `detachFd()`, исключающая double-close и падение/сворачивание приложения.
- 🪟 **Надёжный запуск на Windows Desktop & Server** — исправлены ложные срабатывания Single-Instance мьютекса и ошибка `code 1-11 msg Invalid url` на серверных ОС через нативный `ShellExecuteW`.
- 🔐 **Мультипрофили сетей (Mesh Profiles)** — автоматическая генерация уникальных приватных топиков/ключей, изоляция сетей («Дом», «Офис», «Семья») с переключением на лету.
- 🌊 **Шелковистые графики и честный RTT** — замер задержки реальными UDP-пинг пакетами и визуализация трафика кубическими сплайнами Безье.
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
         │  IP: 100.64.200.1      │   │  IP: 100.64.200.2      │
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
| **Windows** | amd64 | [`NatBypass-v1.5.2-windows-amd64.exe`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Windows 10/11 / Server 2016-2022 (Desktop UI + Трей) |
| **Android** | arm64 / arm / x64 | [`NatBypass-v1.5.2.apk`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR-сканер + Экранный QR) |
| **Linux** | amd64 | [`natbypass-v1.5.2-linux-amd64`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | [`natbypass-v1.5.2-linux-arm64`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **Роутеры MIPS** | mips (Big Endian) | [`natbypass-v1.5.2-router-mips`](https://github.com/jamixm4-crypto/natbypass/releases/latest) | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **Роутеры MIPSLE** | mipsle (Little Endian)| [`natbypass-v1.5.2-router-mipsle`](https://github.com/jamixm4-crypto/natbypass/releases/latest)| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Быстрая установка

### Windows
1. Скачайте [**`NatBypass-v1.5.2-windows-amd64.exe`**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. Запустите файл (для поднятия виртуального адаптера `NatBypass` рекомендуются права администратора).
3. Приложение откроется в нативном графическом окне.

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
1. Скачайте [**`NatBypass-v1.5.2.apk`**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. Нажмите **«📷 Сканировать QR»** и наведите камеру на QR-код во вкладке *«Быстрый старт»* на ПК для мгновенного сопряжения!

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

