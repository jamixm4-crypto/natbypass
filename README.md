# NatBypass

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

> [!NOTE]
> **NatBypass** — это децентрализованный защищённый P2P Mesh VPN, созданный для объединения личных устройств (роутеров Keenetic/OpenWrt, телефонов Android, домашних ПК, NAS и серверов) в единую зашифрованную оверлейную сеть без белого IP и защиты от блокировок DPI/ТСПУ. Весь пользовательский трафик защищён сквозным шифрованием (Noise_IK / ChaCha20-Poly1305), промежуточные узлы сети (**Zero-Knowledge Relays**) не имеют возможности расшифровать данные, а официальные релизы криптографически подписаны ключом **Ed25519**.

---

## ✨ Ключевые возможности

* ⚡ **Pure P2P UDP Mesh:** Прямой обмен сокет-в-сокет через STUN UDP Hole Punching без внешних серверов и без белого IP.
* 🛡️ **AmneziaWG & DPI Bypass:** Защита от ТСПУ/DPI с поддержкой мусорных пакетов (`Jc`), случайных заголовков (`H1`–`H4`) и динамического паддинга (`S1`, `S2`).
* 🔄 **Self-Healing Relay Failover:** При невозможности прямого P2P (двойной Symmetric NAT) трафик автоматически идёт через доверенный узел-ретранслятор с возвратом в прямой P2P при открытии пути.
* 🌐 **Шлюз в интернет (Exit Node):** Выход в интернет через домашний роутер в один клик с изоляцией DNS и защитой от утечек.
* 🚀 **Оптимизация под роутеры:** Чистый Go без CGO, потребление RAM до 48 МБ — стабильная работа даже на роутерах с 64–128 МБ памяти (Keenetic, OpenWrt).
* 🪟 **Нативный Win32 GUI:** Сверхлёгкий интерфейс без Electron и браузера (15–25 МБ RAM) для Windows 10/11 и Windows Server.
* 📱 **Android 10–15 All-in-One:** Системный `VpnService` с быстрым подключением через QR-код.

---

## 🏗️ Архитектура

```
         ┌──────────────────────────────────────────────────────────┐
         │             Сигнальные каналы (E2EE)                     │
         │  [MQTT Mesh Brokers] ── [LAN UDP Discovery] ── [Telegram]│
         └────────▲────────────────────────────────────────▲────────┘
                  │          (зашифрованные маяки)         │
                  │                                        │
    ┌─────────────┴──────────┐                  ┌──────────┴─────────────┐
    │     Узел A (ПК)        │                  │   Узел B (Keenetic)    │
    │  STUN: 37.212.11.11    │                  │  STUN: 37.212.34.205   │
    │  VIP: 10.1.2.171       │                  │  VIP: 10.1.2.217       │
    └─────────────┬──────────┘                  └──────────┬─────────────┘
                  │                                        │
                  └─────────── Direct UDP Socket ──────────┘
                         (P2P Mesh / AmneziaWG)
```

---

## 📦 Поддерживаемые платформы

| Платформа | Архитектура | Исполняемый файл | Описание |
|---|---|---|---|
| **Windows (GUI & WebUI)** | x86_64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass.exe) | Полнофункциональное приложение в отдельном окне (без браузера, WebView2 / App Window, трей) |
| **Windows (Native Win32)** | x86_64 | [NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-GUI.exe) | Сверхлёгкое нативное Win32-приложение (GDI/User32, без браузера, 15–25 МБ RAM) |
| **Windows (CLI / Service)** | x86_64 | [natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-cli.exe) | Консольная утилита для скриптов, автоматизации и службы Windows |
| **Linux (x86_64)** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-amd64) | Серверы Ubuntu, Debian, CentOS, Arch |
| **Linux (ARM64)** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-arm64) | Raspberry Pi 3/4/5, ARM-серверы, Orange Pi |
| **Keenetic (MIPSLE)** | mipsle | [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-keenetic-mipsle) | Keenetic Titan, Hero, Hopper, Speedster, City, Air |
| **OpenWrt (MIPS)** | mips | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-router-mips) | OpenWrt на процессорах Atheros / Qualcomm (Big Endian) |
| **OpenWrt (MIPSLE)** | mipsle | [natbypass-router-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-router-mipsle) | OpenWrt на процессорах MediaTek / Ralink (Little Endian) |
| **Android** | arm64 / universal | [Скачать APK](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 10–15: VpnService, плитка быстрых настроек, QR |

---

## 🚀 Быстрый старт (Установка за 1 минуту)

### 🐧 Роутеры Keenetic, OpenWrt и серверы Linux
Установка демона, службы и автозапуска в одну строку:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
Панель управления доступна по адресу: `http://<IP_УСТРОЙСТВА>:8080`.

### 🪟 Windows
* **[NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass.exe)** — основное приложение для Windows: запускается сразу **в собственном отдельном окне** (без адресной строки и вкладок браузера), имеет системный трей, интерактивную карту топологии и детальные графики.
* **[NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-GUI.exe)** — сверхлёгкая классическая Win32-версия (чистый Windows API, без браузерных движков, потребляет всего 15–25 МБ RAM).
* **[natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-cli.exe)** — консольная утилита для скриптов, автоматизации и установки службы Windows.

### 📱 Android
1. **Установка приложения:**
   * Отсканируйте **QR-код для скачивания** (вкладка `📱 Скачать APK` в окне QR-кода на компьютере) стандартной камерой телефона;
   * Либо скачайте APK вручную со [страницы релизов](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. **Мгновенное подключение к сети:**
   * Откройте установленное приложение **NatBypass Android** на смартфоне.
   * Нажмите кнопку **«📷 Сканировать QR»** и наведите камеру на QR-код профиля сети (`🔒 Профиль`) на экране ПК или роутера — туннель активируется со всеми ключами и настройками!

---

## 🗑️ Удаление и сброс конфигурации (Linux / Keenetic / OpenWrt)

### 1. Полное удаление программы со всеми файлами и ключами:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

### 2. Очистка и сброс конфигурации (Без удаления программы):
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

---

## 🛡️ AmneziaWG (Защита от ТСПУ / DPI)

NatBypass включает встроенную поддержку **AmneziaWG** — протокола с поведенческой обфускацией против глубокого анализа пакетов.

| Пресет | Параметры | Назначение |
|---|---|---|
| **`Anti-TSPU`** | `Jc=4-5`, `S1=56`, `S2=80-100`, рандомизация `H1..H4` | **Рекомендуется для сотовых сетей РФ (МТС, МегаФон, Tele2)** |
| **`Strict`** | Максимальный паддинг, рандомизация таймеров, рандомные трейлеры | Жёсткие корпоративные или государственные DPI |
| **`Balanced`** | Защита заголовков + умеренный паддинг + стандартный keepalive | Оптимальный режим по умолчанию |
| **`Light`** | Минимальный паддинг (`Jc=2`, `S1=32`, `S2=48`) | Домашние оптоволоконные провайдеры (PON / Ethernet) |

Подробная таблица пресетов по операторам связи: [**docs/OPERATOR_PRESETS.md**](docs/OPERATOR_PRESETS.md).

---

## 🔍 Экспресс-диагностика сети

* **Linux / Роутеры:** `curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh`
* **Windows (PowerShell):** `irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex`
* **В WebUI:** кнопка **«⚡ Экспресс-диагностика»** на вкладке «Диагностика».
* **Межсетевой тестер:** утилита [NatBypass-Probe](wiki/Probe-Diagnostics.md) для замера потерь и классификации NAT (RFC 5780).

---

## 📚 Документация и База Знаний

* 🚀 [**Быстрый старт за 5 минут**](wiki/Quick-Start.md) — пошаговое подключение первых устройств.
* 🎮 [**Сценарии использования (Use Cases)**](docs/USE_CASES.md) — сетевые игры с минимальным пингом, доступ к NAS, свой Exit Node.
* 📶 [**База пресетов для сотовых сетей**](docs/OPERATOR_PRESETS.md) — настройки обхода DPI для МТС, МегаФон, Билайн, Tele2, Yota.
* 🌐 [**Keenetic Роутеры**](wiki/Keenetic-Routers.md) & [**OpenWrt**](wiki/OpenWrt-Routers.md) — тонкая настройка роутеров.
* 🛡️ [**Шлюз выхода в интернет (Exit Node)**](wiki/Exit-Node-Guide.md) — настройка домашнего шлюза.
* ⚡ [**Многоуровневый NAT Traversal**](wiki/NAT-Traversal-Explained.md) — преодоление Symmetric NAT и координация пиров.
* 🔐 [**Модель угроз и безопасность**](docs/THREAT_MODEL.md) — формальный аудит и границы защищённости.
* 🗑️ [**Удаление и сброс конфигурации**](wiki/Uninstallation-and-Reset.md) — подробные инструкции по очистке.

---

## 🤝 Стандарты сообщества

* 📋 [**Contributing Guidelines**](CONTRIBUTING.md)
* 🤝 [**Code of Conduct**](CODE_OF_CONDUCT.md)
* 🔒 [**Security Policy**](SECURITY.md)
* 💬 [**Support Guide**](SUPPORT.md)
* 📜 [**Third-Party Licenses**](THIRD_PARTY_LICENSES.md)

---

## 📄 Лицензия

Проект распространяется под свободной лицензией [GNU GPLv3](LICENSE).
