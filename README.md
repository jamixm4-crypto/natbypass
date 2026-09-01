# NatBypass

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

## 📚 [Официальная База Знаний (Wiki)](https://github.com/jamixm4-crypto/natbypass/wiki)

Полная документация и пошаговые инструкции доступны в нашей [**NatBypass Wiki**](https://github.com/jamixm4-crypto/natbypass/wiki):
* 🚀 [**Быстрый старт за 5 минут**](https://github.com/jamixm4-crypto/natbypass/wiki/Quick-Start) — подключение первой P2P-пары устройств без консоли.
* 🛡️ [**Обход блокировок (AmneziaWG 3.1 & 2.0)**](https://github.com/jamixm4-crypto/natbypass/wiki/AmneziaWG-DPI-Bypass) — тюнинг параметров Jc, Jmin, Jmax, S1, S2, H1..H4 против ТСПУ / DPI.
* 🌐 [**Роутеры Keenetic (Entware)**](https://github.com/jamixm4-crypto/natbypass/wiki/Keenetic-Routers) & [**OpenWrt**](https://github.com/jamixm4-crypto/natbypass/wiki/OpenWrt-Routers) — установка в 1 команду и автозапуск.
* 📱 [**Android-руководство**](https://github.com/jamixm4-crypto/natbypass/wiki/Android-Setup) — подключение по QR-коду, отображение QR на экране и системный VpnService.
* 🪟 [**Windows-руководство**](https://github.com/jamixm4-crypto/natbypass/wiki/Windows-Guide) — нативный UI, трей, Wintun и серверный режим.
* 🔧 [**Диагностика и устранение неполадок**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — универсальные скрипты диагностики и сквозной проверки пинга.

---

## ✨ Ключевые возможности

- ⚡ **Pure P2P UDP Mesh:** Прямой датаграммный обмен между узлами через STUN Hole Punching без аренды VPS.
- 🛡️ **AmneziaWG 3.1 & 2.0:** Встроенная защита от Deep Packet Inspection (DPI / ТСПУ) с поддержкой кастомных заголовков (H1..H4), мусорных пакетов (Jc, Jmin, Jmax) и рандомизации паддинга (S1, S2).
- 📡 **Мультиканальная сигнализация:** Обмен пирами и координатами через Telegram Bot API, MQTT, Cloudflare DNS TXT и HTTP Webhook с E2E-шифрованием NaCl/Box (X25519 + XSalsa20-Poly1305).
- 🔄 **Горячая динамическая конфигурация:** Мгновенная смена комнат/топиков, AWG-профилей и виртуальных IP без перезапуска демона.
- 🔍 **Автоматическая диагностика:** Встроенный инструмент динамического обнаружения пиров и L3 ICMP тестирования на всех платформах.
- 📱 **Android All-in-One:** Системный VpnService на чистом Go, сканирование и вывод интерактивного QR-кода на экран, Quick Settings Tile.
- 🪟 **Нативный Windows GUI:** Легковесный интерфейс без CGO, интеграция с системным треем, поддержка Windows Desktop и Server.
- 🔐 **Изолированные профили сетей:** Управление независимыми Mesh-сетями («Дом», «Офис», «Серверы») с переключением на лету.

---

## 🔍 Универсальные утилиты диагностики

В проект встроена полностью **динамическая система диагностики**, которая опрашивает локальный демон, автоматически находит всех подключенных участников меш-сети и поочередно тестирует сквозной L3 ICMP Ping до каждого пира, а также проверяет сетевой стек, STUN-эндпоинты, тип NAT и системные маршруты.

### 🐧 Linux / KeeneticOS / OpenWrt
Запуск в одну команду (не требует установки зависимостей):
```bash
wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh
```
*(или через curl: `curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh`)*

Если у вас уже установлен бинарник `natbypass`:
```bash
natbypass diag
```

### 🪟 Windows (PowerShell)
Запуск диагностического скрипта от имени Администратора:
```powershell
irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex
```
*(или через CLI: `.\NatBypass.exe diag`)*

---

## 🏗️ Архитектура P2P сети

```
              ┌──────────────────────────────────────────────────────────┐
              │             Каналы сигнализации (E2EE)                   │
              │  [Telegram Bot] ── [MQTT Broker] ── [Cloudflare DNS/Web] │
              └────────▲────────────────────────────────────────▲────────┘
                       │          (зашифрованные маяки)         │
                       │                                        │
         ┌─────────────┴──────────┐                  ┌──────────┴─────────────┐
         │    Устройство A        │                  │    Устройство B        │
         │  STUN Discovery        │                  │  STUN Discovery        │
         │  Windows App (Wintun)  │                  │  Keenetic / Linux / Android
         │  VIP: 100.64.200.1     │                  │  VIP: 100.64.200.2     │
         └─────────────┬──────────┘                  └──────────┬─────────────┘
                       │                                        │
                       └─────────── Direct UDP Socket ──────────┘
                                 (P2P Mesh / AWG 3.1)
```

---

## 📦 Поддерживаемые платформы

| Платформа | Архитектура | Файл релиза | Описание |
|---|---|---|---|
| **Windows** | amd64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Windows 10/11 / Server (Desktop UI + Трей + Wintun) |
| **Android** | arm64 / arm / x64 | [NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR-сканер + Экранный QR) |
| **Linux** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **Роутеры MIPS** | mips (Big Endian) | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest) | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **Роутеры MIPSLE** | mipsle (Little Endian)| [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest)| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Быстрая установка

### Windows (10/11 & Windows Server)
1. Скачайте [**NatBypass.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. Запустите файл от имени Администратора для настройки интерфейса Wintun.
3. Приложение откроется в нативном графическом окне.

### Linux / Keenetic / OpenWrt (Установка в 1 команду)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(или через wget: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Панель управления будет доступна по адресу: `http://<IP_УСТРОЙСТВА>:8080`.

---

## 🛡️ AmneziaWG 3.1 & 2.0 (Защита от ТСПУ / DPI)

NatBypass поддерживает **AmneziaWG 3.1** — протокол с поведенческой обфускацией, разработанный для противодействия активным системам ТСПУ и DPI. 

### ⚙️ Доступные пресеты протокола

| Пресет | Версия | Описание | Применение |
|---|---|---|---|
| **`awg31_strict`** | **AWG 3.1** | Header Protection + Random Trailers + Disable Cookies + Content Padding (0-100B) + CPS Packets + рандомизация таймеров | **Максимальное пробитие ТСПУ / DPI** |
| **`awg31_balanced`** | **AWG 3.1** | Header Protection + Random Trailers + Cookies + Content Padding (0-50B) + стандартный джиттер | Рекомендуется для всех сетей по умолчанию |
| **`anti_tspu`** | **AWG 2.0** | Нестандартный тюнинг параметров 2.0 (Jc=5, S2=100, случайные H1..H4) | Улучшенная совместимость |
| **`awg20_legacy`** | **AWG 2.0** | Стандартный WireGuard + AWG 2.0 мусорные пакеты (Jc=4, S1=48, S2=32) | Старые клиенты |

---

## 🗺️ Дорожная карта (Roadmap)

- 🧪 **Исследование и бенчмаркинг резервных протоколов:** В настоящее время ведется тестирование и выбор наиболее стабильных и устойчивых к блокировкам протоколов резервного транспорта (fallback relay) на случай полной изоляции прямого UDP-трафика со стороны провайдеров.
- 🧩 **Адаптивный транспортный менеджер:** Бесшовное авто-переключение между Direct P2P UDP, AmneziaWG и резервными туннелями на основе телеметрии RTT, джиттера и процента потерь пакетов.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).