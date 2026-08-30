# 🗺️ Архитектурная карта проекта NatBypass (Project Map)

> **Версия карты**: Актуальна для релизов серии `v1.9.113+`  
> **Назначение**: Полная техническая шпаргалка и навигатор по архитектуре, модулям, сетевому стеку и потокам данных NatBypass для мгновенной ориентации без необходимости повторного исследования кодовой базы.

---

## 📌 1. Концепция и ключевой стек

**NatBypass** — это децентрализованная, высокопроизводительная P2P Mesh VPN-сеть с нулевой конфигурацией и устойчивостью к блокировкам (DPI / ТСПУ):
- **Язык**: Pure Go 1.22+ (100% без CGO).
- **Плоскость данных (Data Plane)**: Прямой UDP Hole Punching (STUN) + Wintun (Windows) / TUN `/dev/net/tun` (Linux & Keenetic/OpenWrt).
- **Скрытие трафика (Obfuscation)**: Полноценный стек **AmneziaWG 3.1 / 2.0** (мусорные пакеты `Jc/Jmin/Jmax`, кастомные заголовки `H1..H4`, паддинг `S1..S2`, защита заголовков `HeaderProtectionKey` ChaCha20-Poly1305, случайные трейлеры `RandomTrailers`, отключение cookie `DisableCookies`).
- **Плоскость управления (Control Plane)**: Многоканальная децентрализованная сигнализация (MQTT шина, Telegram Bot API, DNS TXT, Webhooks).
- **Интерфейсы**:
  - Native Pure Win32 GDI/User32 GUI (Windows x64, без фреймворков и WebView2, запуск в ~15 МБ ОЗУ).
  - Встроенный WebUI (Single-Page App на ванильном JS/HTML5/CSS3 без внешних CDN, поддержка KeeneticOS/Linux/Windows).
  - CLI / Daemon для встраиваемых роутеров (MIPSLE, MIPS, ARM, ARM64).
  - Go Mobile Bridge (`mobile/`) для Android/iOS.

---

## 📂 2. Структура директорий и исходных файлов

```
e:\qwen\fnat\
├── cmd/
│   ├── natbypass/            # Основной headless-демон (Linux/Windows)
│   │   ├── main.go           # Точка входа, флаги CLI, runtime
│   │   └── engine.go         # Ядро сервиса, TUN I/O, связка с WebUI и P2P
│   ├── natbypass-cli/        # Компактный CLI-клиент для роутеров (Keenetic/OpenWrt)
│   │   ├── main.go           # Точка входа CLI
│   │   └── engine.go         # Облегченный движок P2P и TUN для роутеров
│   └── natbypass-gui/        # Нативный Windows GUI (Pure Win32 GDI/User32)
│       ├── main.go           # Оконные процедуры, Dark Mode, High-DPI, Wintun
│       └── rsrc_windows_amd64.syso # Встроенная иконка и манифест UAC
├── internal/
│   ├── autostart/            # Автозагрузка (Windows Registry Run, Linux systemd, OpenWrt init.d)
│   ├── config/               # Загрузка, сохранение, AES-256-GCM шифрование config.yaml
│   │   ├── config.go         # Базовая структура Config, Defaults, I/O
│   │   └── profiles.go       # Мультипрофили, ExportProfileURI, ImportProfileURI, VIP генератор
│   ├── constants/            # Общесистемные константы (таймауты, префиксы, заголовки)
│   │   └── constants.go      # KeepAlive (8s), ProbeBurstCount (3), TunHeader, PingPrefix
│   ├── crypto/               # Криптография: X25519, ChaCha20-Poly1305, Double Ratchet, BLAKE2s
│   ├── daemon/               # Управление процессами, PID-файлы, graceful shutdown
│   ├── dht/                  # Kademlia DHT для децентрализованного поиска узлов
│   ├── diagnostic/           # Инструменты диагностики (Ping, Traceroute, DNS, MTU)
│   ├── network/              # Сетевой транспорт и пробитие NAT
│   │   ├── puncher.go        # UDPPuncher: STUN discovery, KeepAlive loop, Symmetric NAT prediction
│   │   ├── magicsock.go      # MagicSock: Tailscale-style multipath routing, roaming, candidate switching
│   │   ├── stun.go           # RFC 5389 / 8489 STUN клиент и парсер маппингов
│   │   ├── ip.go             # Определение внешнего IP через многопоточные HTTP/STUN резолверы
│   │   └── shaper.go         # TrafficShaper: маскировка UDP трафика под видеопотоки (DPI bypass)
│   ├── peer/                 # Реестр узлов и отслеживание метрик
│   │   └── registry.go       # PeerRegistry, Upsert, MergeFrom, сглаживание RTT (EMA), IPConflict
│   ├── relay/                # Резервные релей-транспорты
│   │   ├── udp_relay.go      # UDP Relay сервер и клиент
│   │   └── wss_relay.go      # WSS (WebSocket over TLS 443) релей
│   ├── signaling/            # Сигнальные шины обмена пирами
│   │   ├── manager.go        # SignalingManager: параллельная оркестрация каналов
│   │   ├── channel.go        # Payload, AWGParams, шифрование маяков NetworkKey
│   │   ├── mqtt.go           # MQTT транспорт (Paho MQTT, QoS 0, авто-реконнект)
│   │   └── telegram.go       # Telegram Bot API транспорт (Base64 payload, long-polling)
│   ├── tray/                 # Системный трей Windows (Shell_NotifyIconW)
│   ├── tunnel/               # Создание и маршрутизация виртуальных интерфейсов
│   │   ├── tunnel_windows.go # Wintun драйвер, IP/Subnet маршруты, брандмауэр Windows Defender
│   │   ├── tunnel_linux.go   # Linux /dev/net/tun, sysctl rp_filter, iptables/nftables
│   │   └── routing_windows.go# Управление маршрутизацией Windows (route.exe, netsh)
│   ├── updater/              # Автообновление с проверкой цифровой подписи Ed25519
│   ├── webui/                # Встроенный HTTP Web-сервер и API
│   │   ├── server.go         # REST API роуты (/api/status, /api/dashboard, /api/peers, /api/awg/sync...)
│   │   ├── auth_keenetic.go  # Бесшовная аутентификация в KeeneticOS (ndm hashes + probe)
│   │   └── static/           # Встроенные статические файлы (go:embed)
│   │       └── index.html    # Single Page App дашборд, SVG графики, 1-Click AWG Sync, баннер коллизий
│   └── wireguard/            # Генератор конфигов AmneziaWG 3.1 / WireGuard
│       └── awg.go            # AWG 3.1 header obfuscation, случайные параметры, генерация .conf
├── mobile/                   # Go Mobile Bridge
│   └── bridge.go             # Экспорт API для Android AAR (VpnService) и iOS Framework
├── dist/                     # Скомпилированные бинарники всех платформ и рабочий config.yaml
├── build/                    # Промежуточные артефакты сборки
└── winres/                   # Конфигурация PE ресурсов Windows (winres.json)
```

---

## ⚡ 3. Сетевой стек и плоскость данных (Data Plane)

### 1. MagicSock (Smart Multipath Selector)
- **Принцип**: Отслеживает все возможные пути к каждому пиру (LAN IP, IPv6, STUN WAN IP).
- **LAN Priority**: Если пир доступен по локальной сети (`192.168.x.x` / `10.x.x.x`), MagicSock **мгновенно** переключается на LAN с задержкой < 1 мс.
- **Failover & Roaming**: Если активный эндпоинт не отвечает на 3 зонда подряд (`Failures >= 3`), MagicSock автоматически переключается на лучший альтернативный кандидат.
- **Maintenance**: Каждые 10 секунд отправляет легкие зонды кандидатам без создания буферблоата.

### 2. UDP Puncher & STUN
- **Порт по умолчанию**: `47832 UDP`.
- **STUN Discovery**: Опрашивает `stun.l.google.com:19302`, `stun.cloudflare.com:3478` для определения внешнего сокета и типа NAT.
- **Symmetric NAT Traversal**: Предсказание дельты портов (`Port+1, Port+2, Port-1, Port-2, Port+delta`).
- **Auto-KeepAlive Loop**: Каждые 8 секунд отправляет мини-пакет `KAEP` по всем активным эндпоинтам, предотвращая сброс трансляций в таблицах CGNAT провайдеров.

### 3. Стек обфускации AmneziaWG 3.1 / 2.0
| Параметр | Назначение | Значение по умолчанию | Режим Stealth Randomizer |
| :--- | :--- | :--- | :--- |
| **Jc** | Количество мусорных пакетов перед хендшейком | `4` | `3 – 8` (случайное) |
| **Jmin / Jmax** | Размер мусорного пакета (байты) | `40 / 70` | `20 – 120` |
| **S1 / S2** | Паддинг заголовков Init и Response | `48 / 32` | `16 – 64` |
| **H1 .. H4** | Кастомные магические байты заголовков сообщений 1–4 | Дефолтные WireGuard (`1..4`) | Случайный `uint32` (до `4294967295`) |
| **HeaderProtectionKey** | Симметричный ключ шифрования заголовков ChaCha20 | `""` | 32-байтный hex-ключ |
| **RandomTrailers** | Случайный трейлер-паддинг в конце пакетов | `true` | `true` |
| **DisableCookies** | Отключение легко детектируемых cookie-сообщений | `true` | `true` |

---

## 📡 4. Сигнальная плоскость и обнаружение узлов (Control Plane)

- **Периодичность маяков**: Каждые `8 секунд` (`publish_interval: 8`).
- **Синхронизация AWG**: Если узел обнаруживает различие параметров `H1..H4` с сетью, он выставляет флаг `AWGMismatch = true`, отображая в UI кнопку **1-Click Sync**.
- **Детектор коллизий IP**: Если пир в маяке объявляет такой же `VirtualIP`, как у локального узла, выставляется флаг `IPConflict = true` и в WebUI/GUI зажигается аварийный баннер.

---

## 🌐 5. Адресация, профили и маршрутизация

### Формат ссылки профиля (Export URI)
```text
natbypass://profile?id=p-22509283&name=Сеть%201&broker=tcp://broker.emqx.io:1883&topic=natbypass/mesh/00173cf3151bc5f9&key=2bd19ebf27d70ea5ce05be929cdf35b4&subnet=10.123.111.0/24&awg=dpi&h1=2870955547&h2=82743565&h3=1025681256&h4=4133848824&s1=40&s2=37&jc=5&jmin=31&jmax=67&rt=true&dc=true
```

### Правила распределения Virtual IP
- **Подсеть**: Задается создателем сети (например, `10.123.111.0/24` или `100.64.200.0/24`).
- **Шлюз сети (`.1`)**: Резервируется за роутером (Keenetic / OpenWrt / создателем сети).
- **Клиенты (`.2 .. .254`)**: Генерируются детерминированно из `SHA256(DeviceID)` в диапазоне `.2`–`.254` без коллизий.

### Настройка интерфейсов и маршрутов
- **Windows (`tunnel_windows.go`)**:
  - Адаптер Wintun `NatBypass`, IP: `<VIP>/24`.
  - Профиль сети переводится в **`Private`**.
  - Правила брандмауэра: ICMPv4 Type 8 Inbound разрешен (`New-NetFirewallRule` + `netsh`), входящий трафик интерфейса `NatBypass` разрешен.
  - Маршрут: `<SubnetPrefix>.0/24` через интерфейс `NatBypass` с `metric=1`.
- **Linux / Keenetic (`tunnel_linux.go`)**:
  - Интерфейс `nb0`, MTU `1420`, MSS Clamping включен.
  - Ядро: `sysctl -w net.ipv4.conf.all.rp_filter=0`, `accept_local=1`, `icmp_echo_ignore_all=0`.
  - Iptables: `-I INPUT -i nb0 -j ACCEPT`, `-I FORWARD -i nb0 -j ACCEPT`.

---

## 🖥️ 6. Пользовательские интерфейсы

1. **Windows Native GUI (`cmd/natbypass-gui/main.go`)**:
   - Pure GDI/User32 (без CGO, без MFC/Qt/WPF/WebView2).
   - High-DPI V2 aware (1:1 резкость на 4K мониторах).
   - Вкладки: Обзор (живой дашборд), AmneziaWG (настройки обфускации и синхронизация), Сети/Профили, Настройки, Диагностика.
   - Сворачивание в трей с кастомным меню и всплывающими уведомлениями.

2. **Встроенный WebUI (`internal/webui/`)**:
   - Доступен по `http://<IP>:8080`.
   - Живые SVG-графики задержки и пропускной способности.
   - 1-Click AWG Consensus Sync при несовпадении параметров.
   - Встроенные диагностические инструменты: Web-пинг с интерфейса, Traceroute, проверка доступности интернета, карта маршрутов.
   - Автоматическая аутентификация в KeeneticOS без ввода пароля (парсинг `startup-config.draft`).

---

## 🔨 7. Сборка и кросс-компиляция (Build Runbook)

### Окружение сборки (Windows PowerShell)
```powershell
$env:GOROOT="e:\qwen\fnat\soft\go"
$env:GOPATH="e:\qwen\fnat\soft\gopath"
$env:GOCACHE="e:\qwen\fnat\soft\gocache"
$env:CGO_ENABLED="0"
$ver="1.9.113"
$ld="-s -w -X main.Version=$ver"
```

### Команды компиляции всех платформ:

```powershell
# 1. Windows Native GUI (x64)
$env:GOOS="windows"; $env:GOARCH="amd64"
& "e:\qwen\fnat\soft\go\bin\go.exe" run github.com/tc-hib/go-winres@latest make --in winres/winres.json --out cmd/natbypass-gui/rsrc
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="$ld -H=windowsgui" -o dist/NatBypass-GUI.exe ./cmd/natbypass-gui/...

# 2. Windows CLI / Daemon (x64)
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="$ld" -o dist/NatBypass.exe ./cmd/natbypass

# 3. Keenetic Routers (MIPSLE - softfloat)
$env:GOOS="linux"; $env:GOARCH="mipsle"; $env:GOMIPS="softfloat"
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="$ld" -o dist/natbypass-keenetic-mipsle ./cmd/natbypass-cli/...

# 4. OpenWrt / Routers (MIPS Big Endian - softfloat)
$env:GOOS="linux"; $env:GOARCH="mips"; $env:GOMIPS="softfloat"
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="$ld" -o dist/natbypass-router-mips ./cmd/natbypass-cli/...

# 5. Linux x86_64 (Servers / Nextcloud / Ubuntu / Debian)
$env:GOOS="linux"; $env:GOARCH="amd64"; Remove-Item Env:\GOMIPS -ErrorAction SilentlyContinue
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="$ld" -o dist/natbypass-linux-amd64 ./cmd/natbypass-cli/...

# 6. Linux ARM64 (Raspberry Pi 4/5, Orange Pi, VPS)
$env:GOOS="linux"; $env:GOARCH="arm64"
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="$ld" -o dist/natbypass-linux-arm64 ./cmd/natbypass-cli/...
```

---

## 💡 8. Типичные проблемы и правила их решения

| Проблема | Первопричина | Архитектурное решение |
| :--- | :--- | :--- |
| **Скачки пинга до 3000+ мс** | Шторм зондирования (Bufferbloat) при частом burst-опросе | Плавный опрос кандидатов (1 зонд каждые 10с), удаление вложенных циклов probe |
| **Windows не пингуется** | Брандмауэр Windows Defender дропает входящий ICMPv4 | Принудительное включение правила `ICMPv4 Inbound` и перевод Wintun в `Private` |
| **`[AWG: Различается]`** | При создании сети не экспортировались параметры `H1..H4` | `ExportProfileURI` гарантирует экспорт полных AWG-ключей + кнопка 1-Click Sync в UI |
| **Пинг то идет, то пропадает** | Коллизия IP-адресов (два узла заняли `.1`) | Детектор коллизий IP в реальном времени + аварийный баннер в WebUI и GUI |
| **Касперский: HEUR ложное срабатывание** | Отсутствие метаданных PE-ресурсов в `.exe` | Встроенный `.syso` ресурс (`go-winres`) с цифровым манифестом Windows 10/11 |