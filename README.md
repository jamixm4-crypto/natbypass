# NatBypass v1.1.0

P2P Mesh VPN с автоматическим обходом NAT/CGNAT. Соединяет устройства напрямую без выделенного сервера — через STUN UDP Hole Punching. Работает на Windows, Linux, Keenetic, OpenWrt и Android.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.1.0-8b5cf6?style=flat&logo=github)](https://github.com/jamixm4-crypto/natbypass/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#поддерживаемые-платформы)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

## Что нового в 1.1.0

- **Нативный Win32 Desktop UI** — приложение отображается как обычное окно Windows без браузера, со своей иконкой в трее.
- **Адресная книга** — задавайте удобные имена для каждого устройства в сети.
- **Exit Node (Интернет-шлюз)** — раздайте свой интернет другим узлам через WireGuard NAT в один клик.
- **Site-to-Site LAN** — анонсируйте локальную подсеть (например `192.168.1.0/24`) для доступа к роутерам, NAS и принтерам.
- **AmneziaWG 2.0 пресеты** — переключение между обычным WireGuard, режимом обхода DPI и Stealth с ручной настройкой параметров `Jc`, `S1`, `S2`, `H1–H4`.
- **Диагностика связности** — проверка интернета, внешнего IP, STUN, типа NAT (Full Cone / Symmetric / CGNAT) с кнопкой копирования отчёта.
- **Windows DPAPI** — конфигурация и токены шифруются через встроенный механизм Windows Data Protection API.
- **Мгновенный выход** — при закрытии приложения остальные устройства сети немедленно узнают об отключении.

---

## Как это работает

```
              ┌──────────────────────────────────────────────┐
              │          Каналы сигнализации                 │
              │     [MQTT Broker]  ──  [Telegram Bot]        │
              └────────▲─────────────────────────▲──────────┘
                       │  (зашифрованные беконы) │
                       │                         │
         ┌─────────────┴──────────┐   ┌──────────┴─────────────┐
         │    Устройство A        │   │    Устройство B         │
         │  STUN Discovery        │   │  STUN Discovery         │
         │  Win32 Desktop App     │   │  Linux/Router Daemon    │
         │  IP: 10.200.0.1        │   │  IP: 10.200.0.2         │
         └─────────────┬──────────┘   └──────────┬─────────────┘
                       │                         │
                       └──── Direct UDP Tunnel ───┘
                              (P2P / AWG 2.0)
```

Устройства обмениваются зашифрованными маяками через MQTT или Telegram. Когда IP и порт обеих сторон известны, устанавливается прямой UDP-туннель. Промежуточный сервер для передачи трафика не нужен.

---

## Поддерживаемые платформы

| Платформа | Архитектура | Устройства | Файл |
|---|---|---|---|
| **Windows** | amd64 | Windows 10/11, Server 2019/2022 | `NatBypass-v1.1.0.exe` |
| **Linux** | amd64 | Ubuntu, Debian, CentOS, Arch | `natbypass-v1.1.0-linux-amd64` |
| **Linux ARM64** | arm64 | Raspberry Pi 3/4/5, Keenetic Ultra/Giga | `natbypass-v1.1.0-linux-arm64` |
| **Роутеры MIPS** | mips | OpenWrt, MikroTik (Big Endian) | `natbypass-v1.1.0-router-mips` |
| **Роутеры MIPSLE** | mipsle | Keenetic Start/City/Air, Xiaomi 3G/4A | `natbypass-v1.1.0-router-mipsle` |
| **Android** | arm64 | Смартфоны (через Termux или APK) | `natbypass-v1.1.0-android-arm64` |

---

## Быстрый старт

### Windows

1. Скачайте [`NatBypass-v1.1.0.exe`](https://github.com/jamixm4-crypto/natbypass/releases/latest)
2. Запустите — откроется нативное окно приложения
3. В разделе **«Настройки»** введите токен Telegram-бота или адрес MQTT-брокера
4. Нажмите **«💾 Сохранить»** и запустите программу на втором устройстве с теми же параметрами

### Linux / Keenetic / OpenWrt / Raspberry Pi (Установка в 1 команду)

Выполните на сервере или роутере (автоматически определит архитектуру `x86_64`, `ARM64`, `MIPS`, `MIPSLE` и настроит автозапуск службы):

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh)"
```
или через `wget`:
```bash
wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```

После завершения перейдите в веб-панель: `http://<IP_РОУТЕРА>:8080`.

### Android

1. Скачайте [`NatBypass-v1.1.0.apk`](https://github.com/jamixm4-crypto/natbypass/releases/latest) из раздела Releases
2. Запустите приложение, отсканируйте QR-код с экрана ПК для моментального сопряжения!

---

## Разделы интерфейса

| Вкладка | Назначение |
|---|---|
| **Обзор** | Статус подключения, список активных устройств, задержка |
| **Устройства** | Адресная книга, управление именами, пинг узлов |
| **Шлюз / Сети** | Настройка Exit Node и Site-to-Site маршрутов |
| **AmneziaWG 2.0** | Пресеты обхода DPI, экспорт `.conf` файлов |
| **Журнал** | Лог событий в реальном времени |
| **Диагностика** | Проверка интернета, STUN, NAT-типа |
| **Настройки** | Telegram, MQTT, шифрование конфига |

---

## Сборка из исходников

```bash
# Нативный Windows Desktop App
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o NatBypass.exe ./cmd/natbypass-gui

# Linux / Роутер
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o natbypass ./cmd/natbypass

# MIPS для Keenetic/OpenWrt
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags="-s -w" -o natbypass-mipsle ./cmd/natbypass
```

Или используйте **NatBypass Builder** — графический инструмент для сборки под все платформы одновременно.

---

## Документация

- [Быстрый старт за 5 минут](docs/QUICKSTART.md)
- [Настройка AmneziaWG 2.0 и обход DPI](docs/AMNEZIA_WG.md)
- [Установка на роутеры Keenetic](docs/ROUTERS_KEENETIC.md)
- [Установка на OpenWrt](docs/ROUTERS_OPENWRT.md)
- [Android](docs/ANDROID.md)
- [Настройка Telegram и MQTT](docs/SIGNALING_SETUP.md)

---

## Лицензия

[MIT](LICENSE)
