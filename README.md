<div align="center">

# 🛸 NatBypass v1.1.0

**Современное кроссплатформенное приложение для обхода NAT / CGNAT и организации прямого зашифрованного P2P Mesh-доступа между устройствами с поддержкой AmneziaWG 2.0 (DPI Bypass), Exit Node маршрутизации и Windows DPAPI шифрования.**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.1.0-8b5cf6?style=flat&logo=github)](https://github.com/jamixm4-crypto/natbypass/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)
[![Security](https://img.shields.io/badge/Crypto-Windows%20DPAPI%20%2F%20NaCl%20X25519-red)](internal/config)

</div>

---

## ✨ Что нового в версии 1.1.0

* 🎨 **Новый Glassmorphism Dark UI (`#0a0e1a`):** Премиальный темный интерфейс с аппаратным ускорением, неоновыми индикаторами, живыми сетевыми метриками (0% фейковых данных).
* 👥 **Адресная книга и никнеймы:** Возможность задавать удобные имена и закладки для каждого узла вашей Mesh-сети.
* 🌐 **Маршрутизация Exit Node (Интернет-шлюз):** Раздача своего интернета через Wintun/WireGuard NAT в 1 клик или маршрутизация всего внешнего трафика (`0.0.0.0/1`, `128.0.0.0/1`) через удаленный домашний ПК/сервер.
* 🏠 **Site-to-Site LAN Subnets:** Анонсирование локальных подсетей (например, `192.168.1.0/24`) для прямого доступа к роутерам, принтерам и NAS внутри Mesh-сети.
* 🛡️ **AmneziaWG 2.0 Пресеты:** 1-клик переключение режимов обфускации против блокировок ТСПУ/DPI (*Стандартный WireGuard*, *Обход DPI*, *Stealth*) с настройкой `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4` и генерацией `.conf`.
* 🩺 **Мультисерверная диагностика связности:** Комплексный тест интернета (через пул независимых DNS/HTTPS серверов), внешнего IP, STUN UDP-сокетов, NAT-типа (Full Cone / Symmetric / CGNAT) и быстрой кнопкой копирования отчета.
* 🔒 **Windows DPAPI Безопасность:** Автоматическое аппаратное шифрование конфигураций и токенов Telegram/MQTT через Windows Data Protection API (`# NATBYPASS_ENCRYPTED_CONFIG:v1`).

---

## 🌟 Ключевые возможности

* **Прямой P2P UDP Hole Punching (RFC 5389 STUN):** Автоматическое пробитие NAT сокет-в-сокет с минимальной задержкой.
* **Мультиканальная сеть сигнализации (Dual-Channel Parallel Relay):**
  * ⚡ **MQTT Mesh Relay:** Сверхбыстрый постоянный обмен маяками и туннельными пакетами с автопереподключением.
  * 💬 **Telegram Bot API:** Резервный канал связи через защищенные сообщения в личном боте (поддержка SOCKS5 прокси).
* **End-to-End шифрование туннеля (E2EE):** Алгоритмы **ChaCha20-Poly1305** и **NaCl/Box** (Curve25519) обеспечивают абсолютную криптостойкость.
* **100% Pure Go (Zero CGO):** Исполняемые файлы компилируются статически без сторонних C-зависимостей и запускаются на любых роутерах и ОС.

---

## 📐 Архитектура системы

```
                ┌─────────────────────────────────────────────────────────┐
                │          Мультиканальная сеть сигнализации             │
                │        [MQTT Mesh Relay] ── [Telegram Bot API]          │
                └───────────▲─────────────────────────────────▲───────────┘
                            │ (End-to-End Encrypted Beacons)  │
                            │                                 │
           ┌────────────────┴───────────────┐     ┌───────────┴────────────────┐
           │     Устройство A (Клиент)      │     │   Устройство B (Exit Node) │
           │  • STUN Discovery (RFC 5389)   │     │  • STUN Discovery (RFC 5389)│
           │  • Glassmorphism UI (Port 8080)│     │  • Windows IP Forwarding   │
           │  • Wintun Virtual Adapter      │     │  • Wintun NAT Gateway      │
           │  • Local Virtual IP: 10.200.0.1│     │  • Remote VIP: 10.200.0.2  │
           └────────────────┬───────────────┘     └───────────┬────────────────┘
                            │                                 │
                            └─────── Direct Socket-to-Socket ─┘
                                  (UDP P2P Tunnel / AWG 2.0)
```

---

## 🧭 Разделы приложения (Web UI & Desktop)

| Вкладка | Назначение |
|---|---|
| 📊 **Обзор (Dashboard)** | Живые метрики сети, статус прямого P2P сокета, Uptime, быстрая таблица пиров |
| 👥 **Устройства (Devices)** | Адресная книга, назначение никнеймов (`⭐ Имя`), копирование IP (`📋 IP`), пинг |
| 🌐 **Шлюз & Сети (Routing)** | Режим Exit Node (раздача интернета), выбор удаленного шлюза, Site-to-Site LAN |
| 🛡️ **AmneziaWG 2.0** | Пресеты обхода DPI, тонкая настройка мусорных пакетов (`Jc`, `S1/S2`), экспорт `.conf` |
| ⏱️ **Журнал (Timeline)** | Потоковый лог событий в реальном времени с кнопкой копирования `📋` и очистки `🧹` |
| 🩺 **Диагностика** | Комплексный тест связности (Интернет, IP, STUN, NAT-тип) с кнопкой копирования отчета |
| ⚙️ **Настройки** | Настройка Telegram-бота, MQTT брокера, DPAPI шифрование и переключатели логов |

---

## 💻 Поддерживаемые платформы

| Платформа | Архитектура | Целевые устройства | Готовый бинарник |
|---|---|---|---|
| **Windows** | `amd64` | Windows 10/11, Server (Glassmorphism GUI + Service) | `NatBypass-v1.1.0.exe` |
| **Windows CLI** | `amd64` | Консольный режим / службы Windows | `natbypass-v1.1.0-windows-amd64.exe` |
| **Linux** | `amd64` | Ubuntu, Debian, CentOS, Arch | `natbypass-v1.1.0-linux-amd64` |
| **Linux ARM64** | `arm64` | Keenetic Ultra/Giga/Peak, Raspberry Pi 3/4/5 | `natbypass-v1.1.0-linux-arm64` |
| **Routers MIPS** | `mips` *(Big Endian)* | Роутеры OpenWrt, Mikrotik MIPSBE | `natbypass-v1.1.0-router-mips` |
| **Routers MIPSLE**| `mipsle` *(Little Endian)*| Keenetic Start/City/Air, Xiaomi 3G/4A | `natbypass-v1.1.0-router-mipsle` |
| **Android** | `arm64` | Смартфоны (Termux / ADB / AAR / APK) | `natbypass-v1.1.0-android-arm64` |

---

## 🚀 Быстрый старт

### 🪟 Windows (Самый простой способ)
1. Скачайте [**`NatBypass-v1.1.0.exe`**](https://github.com/jamixm4-crypto/natbypass/releases/latest);
2. Запустите файл — откроется окно приложения с Glassmorphism-интерфейсом;
3. В разделе **«Настройки»** укажите токен Telegram-бота или уникальный топик MQTT;
4. Нажмите **«💾 Сохранить настройки»** — всё готово! Запустите программу на втором ПК/роутере с теми же настройками.

### 🐧 Linux / Роутеры
```bash
# Скачивание и запуск
chmod +x natbypass-v1.1.0-linux-amd64
./natbypass-v1.1.0-linux-amd64 start --config config.yaml
```

---

## 📚 Документация по компонентам

* [**🚀 Быстрый старт за 5 минут (docs/QUICKSTART.md)**](docs/QUICKSTART.md) — Пошаговое руководство для начинающих.
* [**🛡️ Настройка AmneziaWG 2.0 (docs/AMNEZIA_WG.md)**](docs/AMNEZIA_WG.md) — Обход блокировок ТСПУ и РКН.
* [**🌐 Настройка роутеров Keenetic (docs/ROUTERS_KEENETIC.md)**](docs/ROUTERS_KEENETIC.md) — Установка на Keenetic OS через Entware.
* [**📡 Настройка роутеров OpenWrt (docs/ROUTERS_OPENWRT.md)**](docs/ROUTERS_OPENWRT.md) — Установка на OpenWrt с интеграцией в `procd`.
* [**📱 Руководство для Android (docs/ANDROID.md)**](docs/ANDROID.md) — Подключение смартфонов к Mesh-сети.
* [**💬 Настройка сигнальных каналов (docs/SIGNALING_SETUP.md)**](docs/SIGNALING_SETUP.md) — Создание Telegram-бота и настройка MQTT.

---

## 📄 Лицензия

Проект распространяется под свободной лицензией [MIT](LICENSE).
