# NatBypass

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

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
* 🔧 [**Диагностика и устранение неполадок**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — расшифровка NAT-типов и проверка связности.

---

## ✨ Ключевые возможности

- ⚡ **Pure P2P UDP Mesh:** Прямой датаграммный обмен между узлами через STUN Hole Punching без аренды VPS.
- 🛡️ **AmneziaWG 3.1 & 2.0:** Встроенная защита от Deep Packet Inspection (DPI / ТСПУ) с поддержкой кастомных заголовков (H1..H4), мусорных пакетов (Jc, Jmin, Jmax) и рандомизации паддинга (S1, S2).
- 📡 **Мультиканальная сигнализация:** Обмен пирами и координатами через Telegram Bot API, MQTT, Cloudflare DNS TXT и HTTP Webhook с E2E-шифрованием NaCl/Box (X25519 + XSalsa20-Poly1305).
- 🔄 **Отказоустойчивый транспорт:** Автоматический переход Direct P2P UDP ➔ AmneziaWG 2.0 ➔ MQTT Datagram Stream Relay при симметричном NAT или жесткой фильтрации.
- 📱 **Android All-in-One:** Системный VpnService на чистом Go, сканирование и вывод интерактивного QR-кода на экран, Quick Settings Tile.
- 🪟 **Нативный Windows GUI:** Легковесный интерфейс без CGO, интеграция с системным треем, поддержка Windows Desktop и Server.
- 🔐 **Изолированные профили сетей:** Управление независимыми Mesh-сетями («Дом», «Офис», «Серверы») с переключением на лету.

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


---

## 🛡️ AmneziaWG 3.1 (Максимальное пробитие ТСПУ / DPI)

NatBypass поддерживает **AmneziaWG 3.1** — передовой протокол с поведенческой обфускацией, разработанный для противодействия активным системам ТСПУ и DPI. В отличие от версий 1.x/2.0, AWG 3.1 маскирует не только статические заголовки, но и статистические паттерны потока данных.

### 🚀 Работа из коробки (По умолчанию):
**Вам не требуется вручную настраивать конфиг** — максимальная защита от ТСПУ (**AmneziaWG 3.1 Strict**, порт **443**, **Header Protection ChaCha20**, **Random Trailers** и **Content Padding**) уже активирована по умолчанию для всех новых подключений и сетей. Каждое устройство автоматически генерирует уникальные криптографические ключи и заголовки обфускации.

### ⚙️ Доступные пресеты протокола

| Пресет | Версия | Описание | Применение |
|---|---|---|---|
| **`awg31_strict`** | **AWG 3.1** | Header Protection + Random Trailers + Disable Cookies + Content Padding (0-100B) + CPS Packets + рандомизация таймеров | **Максимальное пробитие ТСПУ / DPI** |
| **`awg31_balanced`** | **AWG 3.1** | Header Protection + Random Trailers + Cookies + Content Padding (0-50B) + стандартный джиттер | Рекомендуется для всех сетей по умолчанию |
| **`anti_tspu`** | **AWG 2.0** | Нестандартный тюнинг параметров 2.0 (Jc=5, S2=100, случайные H1..H4) | Улучшенная совместимость |
| **`awg20_legacy`** | **AWG 2.0** | Стандартный WireGuard + AWG 2.0 мусорные пакеты (Jc=4, S1=48, S2=32) | Старые клиенты |

### 🔐 Ключевые механизмы защиты AWG 3.1

1. **Header Protection (ChaCha20):** Полное шифрование незашифрованных служебных полей WireGuard (Init: 148B, Response: 92B, Cookie: 64B, Data: 16B). Сигнатурный DPI не видит типичных идентификаторов пакетов.
2. **Content Padding:** Случайное добавление байтов к полезной нагрузке в пределах MTU для устранения корреляции размеров пакетов.
3. **Custom Timings (Диапазоны таймеров):**
   - RekeyAfterTime: 120–180 сек
   - RekeyTimeout: 5–15 сек
   - RejectAfterTime: 180–240 сек
   - KeepaliveTimeout: 5–30 сек
   - MaxHandshakeAttempts: 3–7
4. **Random Trailers & Disable Cookies:** Добавление энтропии в хвост пакетов и отключение ответов на cookie для защиты от активного зондирования (active probing).

### 🔄 Автоматическая миграция

Для быстрого перехода существующего узла на AWG 3.1 выполните скрипт:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/migrate_to_awg31.sh | bash
```

## 🗺️ Дорожная карта (Roadmap)

- 🚀 **Hysteria 2 / QUIC Congestion Control:** Внедрение легковесного UDP-транспорта на базе протоколов QUIC / Hysteria 2 с алгоритмом Brutal Congestion Control для достижения максимальной скорости на нестабильных каналах с высоким процентом потерь пакетов (lossy networks).
- 🧩 **Динамический выбор транспорта:** Автоматическое бесшовное переключение между Direct UDP, AWG 2.0 и QUIC-транспортом на основе метрик RTT, jitter и packet loss.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
