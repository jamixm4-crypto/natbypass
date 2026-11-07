# NatBypass

**P2P Mesh VPN & DPI Bypass** — прямое сокет-в-сокет соединение компьютеров, серверов, телефонов и роутеров через любые виды NAT/CGNAT без выделенных серверов.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

> [!NOTE]
> ### 🛡️ Назначение проекта и Дисклеймер безопасности (Security & Anti-Malware Disclaimer)
> **NatBypass** — это децентрализованный защищённый P2P Mesh VPN, созданный исключительно для обеспечения персональной приватности, объединения личных устройств (роутеров Keenetic/OpenWrt, телефонов Android, домашних ПК, NAS и серверов) в единую защищённую оверлейную сеть и защиты от цензуры DPI.
> 
> * **Не является инструментом для пентеста:** NatBypass **НЕ ЯВЛЯЕТСЯ** средством тестирования на проникновение, сканером портов, бэкдором или утилитой несанкционированного доступа. Проект **не имеет никакого отношения** к сторонним инструментам туннелирования (таким как `cw1997/NATBypass`, `lcx` и подобным).
> * **Сквозное E2EE шифрование:** Весь пользовательский трафик защищён сквозным шифрованием (Noise_IK / ChaCha20-Poly1305 / NaCl Box). Промежуточные узлы сети (**Zero-Knowledge Relays**) не имеют технической возможности расшифровать, просмотреть или модифицировать данные пользователей.
> * **Подписанные релизы:** Все исполняемые файлы криптографически подписаны ключом **Ed25519** и Sigstore/Cosign. Встроенный автообновлятор отклоняет любые неподписанные файлы, защищая от подмены трафика на прокси/зеркалах.
> * **Безопасность WebUI:** Панель управления по умолчанию привязывается строго к `127.0.0.1` (кроме роутеров Keenetic для доступа из домашней LAN), защищена токенами, CSRF-защитой и фильтром DNS Rebinding.

---

## 📚 Документация и База Знаний

* 🚀 [**Быстрый старт за 5 минут**](https://github.com/jamixm4-crypto/natbypass/wiki/Quick-Start) — подключение первой P2P-пары устройств без консоли.
* 🎮 [**Практические сценарии использования (Use Cases)**](docs/USE_CASES.md) — сетевые игры с 0 задержкой, доступ к домашнему NAS/Plex без белого IP, свой Exit Node.
* 📶 [**База пресетов для сотовых операторов (МТС, МегаФон, Билайн, Tele2, Yota)**](docs/OPERATOR_PRESETS.md) — настройки AmneziaWG и портов для преодоления блокировок и CGNAT.
* 🛡️ [**Обход блокировок (AmneziaWG)**](https://github.com/jamixm4-crypto/natbypass/wiki/AmneziaWG-DPI-Bypass) — тюнинг параметров Jc, Jmin, Jmax, S1, S2, H1..H4 против ТСПУ / DPI.
* 🔐 [**Модель угроз и безопасность (Threat Model)**](docs/THREAT_MODEL.md) — формальный аудит защищённости, границы доверия и безопасность ретрансляторов.
* 🌐 [**Роутеры Keenetic (Entware)**](https://github.com/jamixm4-crypto/natbypass/wiki/Keenetic-Routers) & [**OpenWrt**](https://github.com/jamixm4-crypto/natbypass/wiki/OpenWrt-Routers) — установка в 1 команду и автозапуск.
* 📱 [**Android-руководство**](https://github.com/jamixm4-crypto/natbypass/wiki/Android-Setup) — подключение по QR-коду, отображение QR на экране и системный VpnService.
* 🪟 [**Windows-руководство**](https://github.com/jamixm4-crypto/natbypass/wiki/Windows-Guide) — нативный UI, трей, Wintun и серверный режим.
* 🧪 [**Обновление и Тестовые Сборки (Beta)**](https://github.com/jamixm4-crypto/natbypass/wiki/Updating-and-Beta-Versions) — обновление в 1 клик на Windows, Linux, роутерах и Android.
* 🔧 [**Диагностика и устранение неполадок**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — универсальные скрипты диагностики и сквозной проверки пинга.
* 🌍 [**natbypass-probe: Межгеографическая диагностика**](docs/PROBE.md) — утилита для тестирования P2P/AWG-соединений между узлами в разных странах (BY, RU, US).
* ⚡ [**Многоуровневый NAT Traversal**](docs/NAT_TRAVERSAL.md) — 5 уровней преодоления CGNAT мобильных сетей, значки ⚡ Координатор и 🛡️ Relay.
* 📜 [**Лицензии сторонних библиотек**](THIRD_PARTY_LICENSES.md) — аудит зависимостей (WireGuard, Wintun, NaCl, Pion STUN).

---

## ✨ Ключевые возможности

- ⚡ **Pure P2P UDP Mesh:** Прямой датаграммный обмен между узлами через STUN Hole Punching без аренды VPS.
- 🛡️ **AmneziaWG Obfuscation:** Встроенная защита от Deep Packet Inspection (DPI / ТСПУ) с поддержкой кастомных заголовков (H1..H4), мусорных пакетов (Jc, Jmin, Jmax), защиты заголовков и рандомизации паддинга (S1, S2).
- 🔄 **Self-Healing Relay Failover:** При невозможности прямого P2P (двойной Symmetric NAT) трафик автоматически направляется через промежуточный узел-ретранслятор (Zero-Knowledge Multi-Hop), а при восстановлении прямого пути бесшовно возвращается на 100% прямой P2P.
- 🌐 **Шлюз выхода в интернет (Exit Node):** Любой узел сети (Linux, Keenetic, Windows, Android) может выступать защищенным интернет-шлюзом в один клик с изоляцией DNS (`1.1.1.1`, `8.8.8.8`) и обходом локальных провайдерских ограничений.
- 📡 **Мультиканальная сигнализация:** Обмен пирами и координатами через Telegram Bot API, MQTT, Cloudflare DNS TXT и HTTP Webhook с E2E-шифрованием NaCl/Box (X25519 + XSalsa20-Poly1305).
- 🚀 **Оптимизация под MIPS / ARM роутеры:** Чистый Go без CGO, пул буферов `sync.Pool`, ограничение сборщика мусора до 48 МБ RAM, асинхронное логирование — стабильная работа даже на роутерах с 64–128 МБ памяти (Keenetic, OpenWrt).
- 🔄 **Горячая динамическая конфигурация:** Мгновенная смена комнат/топиков, параметров обфускации и виртуальных IP без перезапуска демона.
- 🔍 **Автоматическая диагностика:** Встроенный инструмент динамического обнаружения пиров и L3 ICMP тестирования на всех платформах.
- 📱 **Android 10–15 All-in-One:** Системный асинхронный VpnService (`systemExempted`), сканирование и вывод интерактивного QR-кода на экран, Quick Settings Tile.
- 🪟 **Нативный Windows GUI:** Легковесный интерфейс без CGO/Electron (15–25 МБ RAM), интеграция с системным треем, поддержка Windows Desktop и Server.
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
*(или через CLI: `.\natbypass-cli.exe diag`)*

### 🌍 Межгеографическая P2P/DPI диагностика (natbypass-probe)
Автономная утилита для выявления блокировок UDP, WireGuard-паттерна и параметров AmneziaWG между узлами в разных странах (РФ, РБ, США):

**Linux (быстрый запуск в 1 строку):**
```bash
curl -sSL -o natbypass-probe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe
./natbypass-probe --config probe.json --label "US / VPS" --country US --out report-us.json
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri "https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-Probe.exe" -OutFile "natbypass-probe.exe"
.\natbypass-probe.exe --config probe.json --label "РФ / Ростелеком" --country RU --out report-ru.json
```
Подробная инструкция, создание `probe.json` и флаги: [**docs/PROBE.md**](docs/PROBE.md).

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
                                 (P2P Mesh / AmneziaWG)
```

---

## ⚡ Как работает многоуровневое пробитие NAT

В NatBypass реализована автономная **5-уровневая система NAT Traversal**, позволяющая мобильным клиентам за симметричным CGNAT (МТС, МегаФон, Билайн, Tele2) соединяться напрямую или через mesh-релеи **без аренды внешних серверов с белым IP**:

| Уровень | Технология | Описание |
|---|---|---|
| **Уровень 1** | **IPv6 Dual-Stack P2P** | Параллельное AAAA STUN-обнаружение и прямой P2P-канал через IPv6 в обход IPv4 CGNAT оператора. |
| **Уровень 2** | **DPI Drop Detection** | При 10 безответных пробах (блокировка ТСПУ) автоматически включается `awg31_strict` с обфускацией заголовков на 10 минут. |
| **Уровень 3** | **Leader-Coordinated Punch** | Синхронный залп открытия портов с миллисекундной точностью по команде узла с открытым NAT. |
| **Уровень 4** | **ASN-Aware Port Prediction** | Селективное предсказание шага портов (+2, +4) по базе операторов РФ; случайные пулы исключаются для защиты аккумулятора. |
| **Уровень 5** | **Peer-as-Relay** | Автоматический E2EE транзит через доверенные домашние роутеры (Keenetic, OpenWrt, ПК) в пределах суточных квот (5 ГБ/сутки). |

### 🎯 Что означают значки в WebUI и Android:
- ⚡ **Координатор** (`coordinator_capable`) — узел с открытым/Full-Cone NAT или статическим IP. Координирует одновременное открытие портов для двух мобильных клиентов, помогая им установить прямой P2P-канал.
- 🛡️ **Relay** (`relay_capable`) — узел (роутер Keenetic, Linux-сервер или домашний ПК) с включенным `enable_relay_server: true`. Готов брать на себя транзит трафика при полной изоляции UDP оператором. *(Мобильные устройства на Android автоматически исключаются из релеев при мобильной сети или низком заряде батареи).*
- 🌐 **Интернет-шлюз** (`is_exit_node`) — узел разрешил использовать себя как защищенный выход в интернет (Exit Node).
- 🏠 **Маршрут подсети** (`advertised_routes`) — узел открывает доступ к своей локальной сети (например, домашней `192.168.1.0/24`).

👉 Подробное описание всех 5 уровней: [**docs/NAT_TRAVERSAL.md**](docs/NAT_TRAVERSAL.md).

---

## 📦 Поддерживаемые платформы

| Платформа | Архитектура | Файл релиза | Описание |
|---|---|---|---|
| **Windows (WebUI)** | amd64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11** (Панель управления в браузере `http://localhost:8080` + трей + Wintun) |
| **Windows (GUI)** | amd64 | [NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11** и **Windows Server (2016/2019/2022/2025)** (Чистый нативный Win32 GUI без браузера, 15 МБ RAM + трей) |
| **Windows (CLI)** | amd64 | [natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11 / Server** (Консольная версия для скриптов, служб и автоматизации) |
| **Android** | arm64 / arm / x64 | [NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR-сканер + Экранный QR) |
| **Linux** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **Роутеры MIPS** | mips (Big Endian) | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest) | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **Роутеры MIPSLE** | mipsle (Little Endian)| [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest)| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Быстрая установка

### Windows
* **Windows 10 / 11 (Версия с WebUI):**
  1. Скачайте [**NatBypass.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
  2. Запустите от имени Администратора для настройки интерфейса Wintun. Откроется интерфейс в браузере по адресу `http://localhost:8080`.
* **Windows 10 / 11 и Windows Server (Версия с нативным GUI):**
  1. Скачайте [**NatBypass-GUI.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
  2. Запустите от имени Администратора. Откроется легкое нативное Win32-окно (не требует браузера, WebView2 или Electron, потребляет всего 15–25 МБ RAM, идеально для серверных ОС).
* **Windows Server / Headless (CLI):**
  1. Скачайте [**natbypass-cli.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest). Запуск: `.\natbypass-cli.exe -c config.yaml`.

### Linux / Keenetic / OpenWrt (Установка в 1 команду)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(или через wget: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Панель управления будет доступна по адресу: `http://<IP_УСТРОЙСТВА>:8080` (на Keenetic аутентификация через пароль администратора роутера).

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

NatBypass включает поддержку **AmneziaWG** — протокола с поведенческой обфускацией, разработанного для противодействия активным системам ТСПУ и DPI.

### ⚙️ Доступные пресеты протокола

| Пресет | Описание | Применение |
|---|---|---|
| **`Strict`** | Header Protection + Random Trailers + Disable Cookies + Content Padding + CPS Packets + рандомизация таймеров | **Максимальное пробитие ТСПУ / DPI** |
| **`Balanced`** | Header Protection + Random Trailers + Cookies + Content Padding + стандартный джиттер | Рекомендуется для всех сетей по умолчанию |
| **`Anti-TSPU`** | Нестандартный тюнинг параметров (Jc=5, S2=100, случайные H1..H4) | Сотовые сети (МТС, МегаФон, Tele2) |
| **`Legacy`** | Стандартный WireGuard + мусорные пакеты (Jc=4, S1=48, S2=32) | Старые клиенты |

Полная таблица пресетов для сотовых операторов: [**docs/OPERATOR_PRESETS.md**](docs/OPERATOR_PRESETS.md).

---

## ⚖️ Правовой статус и соблюдение законодательства (Legal Compliance)

Проект NatBypass предназначен для защиты личных данных, обеспечения конфиденциальности и безопасного удалённого доступа к собственным устройствам. Пользователи несут персональную ответственность за соблюдение местного законодательства страны своего пребывания при использовании средств криптографии и VPN.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [GNU GPLv3](LICENSE). Лицензии сторонних библиотек и компонентов приведены в [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
