# NatBypass

**Высокопроизводительный децентрализованный P2P Mesh VPN с обфускацией AmneziaWG и пробитием NAT для Keenetic, OpenWrt, Windows, Linux и Android.**

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

> [!NOTE]
> ### 🛡️ Назначение проекта и Дисклеймер безопасности
> **NatBypass** создан исключительно для обеспечения личной приватности, объединения домашних устройств (роутеров Keenetic/OpenWrt, ПК, смартфонов) в единую защищённую P2P-сеть и устойчивости к блокировкам DPI.
> * **Не является инструментом для пентеста:** NatBypass **НЕ ЯВЛЯЕТСЯ** средством несанкционированного доступа или сканером уязвимостей и не имеет отношения к сторонним утилитам туннелирования (таким как `cw1997/NATBypass` или `lcx`).
> * **Сквозное шифрование (E2EE):** Трафик защищён Noise_IK / ChaCha20-Poly1305. Промежуточные узлы сети (**Zero-Knowledge Relays**) не имеют технической возможности расшифровать данные.
> * **Подписанные релизы:** Все исполняемые файлы криптографически подписаны ключом **Ed25519** и Cosign. Неподписанные файлы отклоняются встроенным автообновлением.

---

## ✨ Ключевые возможности

* ⚡ **Pure P2P UDP Mesh:** Прямой датаграммный обмен сокет-в-сокет через STUN Hole Punching без аренды внешних VPS.
* 🛡️ **AmneziaWG 3.1 & DPI Bypass:** Защита от ТСПУ/DPI с поддержкой мусорных пакетов (`Jc`), случайных заголовков (`H1`–`H4`) и динамического паддинга (`S1`, `S2`).
* 🔄 **Self-Healing Relay Failover:** При невозможности прямого соединения (двойной Symmetric NAT) трафик прозрачно идёт через доверенный узел-ретранслятор, возвращаясь на 100% прямой P2P при открытии пути.
* 🌐 **Шлюз в интернет (Exit Node):** Выход в интернет через домашний роутер в один клик с изоляцией DNS.
* 🚀 **Оптимизация под роутеры:** Чистый Go без CGO, потребление RAM до 48 МБ — стабильная работа даже на роутерах с 64–128 МБ памяти (Keenetic, OpenWrt).
* 🪟 **Нативный Win32 GUI:** Сверхлёгкий интерфейс без Electron и браузера (15–25 МБ RAM) для Windows 10/11 и Server.
* 📱 **Android 10–15 All-in-One:** Системный VpnService с интерактивным обменом через QR-код.

---

## 🏗️ Архитектура

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
    │  Windows (Wintun)      │                  │  Keenetic / Android    │
    │  VIP: 100.64.200.1     │                  │  VIP: 100.64.200.2     │
    └─────────────┬──────────┘                  └──────────┬─────────────┘
                  │                                        │
                  └─────────── Direct UDP Socket ──────────┘
                            (P2P Mesh / AmneziaWG)
```

---

## 🚀 Быстрый старт (Установка за 1 минуту)

### 🐧 Роутеры Keenetic, OpenWrt и серверы Linux
Установка демона и автозапуска в одну строку:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
Панель управления доступна по адресу: `http://<IP_УСТРОЙСТВА>:8080`.

### 🪟 Windows (Desktop и Server)
* **[NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest)** — нативный лёгкий интерфейс (Win32, трей, Wintun).
* **[NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest)** — фоновая служба с Web-панелью `http://localhost:8080`.
* **[natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest)** — консольная утилита для скриптов.

### 📱 Android
* Скачайте **[NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest)** для подключения смартфона по QR-коду.

---

## 🔍 Экспресс-диагностика сети

Запуск проверки сети, STUN и пиров в одну команду:
* **Linux / Роутеры:** `curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh`
* **Windows (PowerShell):** `irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex`
* **В WebUI:** кнопка **«⚡ Диагностика одной кнопкой»** на вкладке «Диагностика».

---

## 📚 Документация и База Знаний

Вся подробная техническая документация вынесена в разделы Wiki и `docs/`:

* 🚀 [**Быстрый старт за 5 минут**](wiki/Quick-Start.md) — пошаговое подключение первых устройств.
* 🎮 [**Сценарии использования (Use Cases)**](docs/USE_CASES.md) — сетевые игры с 0 задержкой, доступ к домашнему NAS, свой Exit Node.
* 📶 [**База пресетов для сотовых сетей (МТС, МегаФон, Билайн, Tele2, Yota)**](docs/OPERATOR_PRESETS.md) — настройки обхода DPI.
* 🌐 [**Keenetic Роутеры**](wiki/Keenetic-Routers.md) & [**OpenWrt**](wiki/OpenWrt-Routers.md) — тонкая настройка роутеров.
* 🛡️ [**Шлюз выхода в интернет (Exit Node)**](wiki/Exit-Node-Guide.md) — настройка безопасного шлюза.
* ⚡ [**Многоуровневый NAT Traversal**](wiki/NAT-Traversal-Explained.md) — преодоление Symmetric NAT и координация пиров.
* 🔐 [**Модель угроз и безопасность**](docs/THREAT_MODEL.md) — формальный аудит и границы защищённости.
* 🗑️ [**Удаление и сброс конфигурации**](wiki/Uninstallation-and-Reset.md) — чистка и удаление программы.

---

## 🤝 Стандарты сообщества (Community Standards)

* 📋 [**Руководство по участию в разработке (Contributing Guidelines)**](CONTRIBUTING.md)
* 🤝 [**Кодекс поведения (Code of Conduct)**](CODE_OF_CONDUCT.md)
* 🔒 [**Политика безопасности (Security Policy)**](SECURITY.md)
* 💬 [**Поддержка и каналы связи (Support Guide)**](SUPPORT.md)
* 📜 [**Лицензии сторонних компонентов (Third-Party Licenses)**](THIRD_PARTY_LICENSES.md)

---

## 📄 Лицензия

Проект распространяется под свободной лицензией [GNU GPLv3](LICENSE).
