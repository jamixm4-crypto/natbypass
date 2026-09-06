# NatBypass Probe — Диагностика межгеографических соединений

`natbypass-probe` — автономная утилита для тестирования возможности установки P2P/AWG-соединений между узлами в разных странах. Помогает выявить, что именно блокирует соединение: NAT, файервол, DPI или ТСПУ.

---

## Когда использовать

Запускайте probe-тест если:
- Узлы видят друг друга как **P2P в интерфейсе**, но пинги не проходят
- Клиенты из определённой страны (РФ, РБ и т.д.) не могут установить соединение
- Нужно понять, что именно блокирует — UDP, WireGuard-паттерн, или AWG-специфика
- После настройки сети нужна верификация реальной связности всех пар

---

## Загрузка

Скачайте с [GitHub Releases](https://github.com/jamixm4-crypto/natbypass/releases/latest):

| Платформа | Файл |
|-----------|------|
| Windows x64 | `natbypass-probe.exe` |
| Linux x64 | `natbypass-probe-linux-amd64` |

> **Примечание:** На Linux выполните `chmod +x natbypass-probe-linux-amd64` перед запуском.

---

## 🚀 Быстрый старт через консоль (One-Liners)

### 🐧 Linux (VPS, сервер, Nextcloud, Ubuntu / Debian / CentOS / Alpine)

#### Вариант А: Вы организатор теста (первый узел)
```bash
# 1. Скачивание утилиты через curl (или wget) и выдача прав
curl -sSL -o natbypass-probe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe

# (Если GitHub заблокирован, через CDN-зеркало):
# curl -sSL -o natbypass-probe https://ghproxy.net/https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe
# или через wget:
# wget -O natbypass-probe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe

# 2. Инициализация единого конфига probe.json
./natbypass-probe --init

# 3. Передайте созданный файл probe.json остальным участникам (в РФ, РБ, США)

# 4. Запуск тестирования на своём узле (с сохранением JSON-отчёта)
./natbypass-probe --config probe.json --label "US / Oracle VPS" --country US --out report-us.json
```

#### Вариант Б: Вы участник (получили файл `probe.json`)
```bash
# 1. Скачивание утилиты
curl -sSL -o natbypass-probe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe

# 2. Положите выданный probe.json в ту же папку (или скачайте по ссылке от организатора):
# curl -sSL -o probe.json https://ваш-сервер.com/probe.json

# 3. Запуск тестирования (укажите свою страну и понятную метку)
./natbypass-probe --config probe.json --label "Nextcloud / Debian" --country RU --out report-ru.json

# 4. Просмотр готового отчёта
cat report-ru.json
```

---

### 🪟 Windows (PowerShell / cmd)

#### Вариант А: Вы организатор теста
```powershell
# 1. Скачивание утилиты в текущую папку через PowerShell или curl.exe
Invoke-WebRequest -Uri "https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-Probe.exe" -OutFile "natbypass-probe.exe"
# или через curl:
# curl.exe -sSL -o natbypass-probe.exe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-Probe.exe

# 2. Инициализация единого конфига probe.json
.\natbypass-probe.exe --init

# 3. Передайте созданный файл probe.json остальным участникам

# 4. Запуск тестирования
.\natbypass-probe.exe --config probe.json --label "РБ / Beltelecom" --country BY --out report-by.json
```

#### Вариант Б: Вы участник (получили `probe.json`)
```powershell
# 1. Скачивание утилиты
Invoke-WebRequest -Uri "https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-Probe.exe" -OutFile "natbypass-probe.exe"

# 2. Положите probe.json рядом с exe и запустите тестирование:
.\natbypass-probe.exe --config probe.json --label "РФ / Ростелеком" --country RU --out report-ru.json

# 3. Просмотр отчёта:
Get-Content report-ru.json
```

---

## Пошаговое руководство (Workflow)

### Шаг 1 — Организатор создаёт конфиг
Один участник (администратор) создаёт общий конфиг:
```bash
./natbypass-probe --init --config probe.json
```
Файл `probe.json` создаётся с вашим AWG-профилем и настройками MQTT. Передайте этот файл **всем остальным участникам** (через мессенджер, email и т.д.).

### Шаг 2 — Каждый участник запускает утилиту
Все узлы запускают тест практически одновременно (в окне ~5 минут):

```bash
# Windows (Беларусь / Beltelecom)
.\natbypass-probe.exe --config probe.json --label "РБ / Beltelecom" --country BY

# Windows (Россия / Ростелеком)
.\natbypass-probe.exe --config probe.json --label "РФ / Ростелеком" --country RU

# Linux (США / VPS)
./natbypass-probe --config probe.json --label "США / VPS" --country US
```

Дополнительные флаги:

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--config` | `probe.json` | Путь к конфиг-файлу |
| `--label` | hostname | Метка узла (страна/провайдер) |
| `--country` | — | Код страны: `BY`, `RU`, `US`, `DE`... |
| `--timeout` | из конфига (300) | Максимальное время теста в секундах |
| `--port` | `19876` | UDP-порт для приёма probe-пакетов |
| `--out` | авто | Путь для сохранения JSON-отчёта |
| `--node` | авто по hostname | Принудительный ID узла |

### Шаг 3 — Сохраните отчёт и передайте разработчику

Каждый участник сохраняет свой отчёт:

```
natbypass-probe.exe --config probe.json --label "РФ/RTK" --out report-ru.json
```

Соберите отчёты всех участников: `report-by.json`, `report-ru.json`, `report-us.json` — и передайте разработчику для анализа.

---

## Как работает обнаружение пиров

Утилита использует **MQTT для обнаружения узлов** — каждый участник публикует свой beacon с:
- Hostname и метка (страна/провайдер)
- STUN-адрес (внешний IP:порт)
- Тип NAT (Full Cone, Restricted, Symmetric)
- Публичный WireGuard-ключ
- UDP-порт probe listener'а

Узлы находят друг друга в течение **60 секунд** после запуска. Все участники должны запустить утилиту в течение ~5 минут друг от друга.

```
[PEER] Discovered node-ru-01 (РФ / Ростелеком): stun=91.214.76.7:4634 nat=symmetric
[PEER] Discovered node-us-01 (США / VPS): stun=144.172.114.55:47832 nat=full_cone
```

---

## Фазы тестирования

### Phase 1: Self-test (0–30 сек)
```
[STUN] stun.l.google.com:19302 → 37.212.8.166:3275 (42ms)
[STUN] stun1.l.google.com:3478 → 37.212.8.166:3281 (48ms)
[STUN] stun.cloudflare.com:3478 → 37.212.8.166:3287 (51ms)
[STUN] NAT type: FULL_CONE
[UDP-SRV] Probe listener on 0.0.0.0:19876
```

### Phase 2: Discovery (0–60 сек)
Узлы публикуют беконы через MQTT и обнаруживают друг друга.

### Phase 3: Тесты соединений
Для каждой пары A→B выполняется:

| Тест | Что проверяет |
|------|--------------|
| **3a. Raw UDP punch** | Проходит ли UDP вообще (без WireGuard) |
| **3b. AWG handshake** | Устанавливается ли WireGuard-соединение с AWG-обфускацией |
| **3c. TCP connect** | Доступны ли TCP-порты 443/80/8080/22/3478 |
| **3d. DPI probe** | Что именно блокирует DPI: plain WG, AWG с текущими H, или AWG вообще |

---

## Пример вывода

```
======================================================================
 NatBypass Probe — Report: probe-igarage-radio-2521
 Узел: node-by-01 | Длительность: 183s | Пиров: 2
======================================================================

[SELF] IGARAGE-RADIO | STUN: 144.172.114.55:47832 | NAT: SYMMETRIC (Δ=0)

ОБНАРУЖЕННЫЕ УЗЛЫ:
  node-ru-01   РФ / Ростелеком   91.214.76.7:4634      symmetric    10.99.89.1
  node-us-01   США / VPS         185.200.110.5:47832   full_cone    10.99.23.1

РЕЗУЛЬТАТЫ ТЕСТОВ:
  ✅ node-by-01>node-us-01:
     AWG P2P работает: ping avg=88ms loss=0%

  🔴 node-by-01>node-ru-01:
     UDP punch OK, но WireGuard handshake не проходит.
     Вероятно ТСПУ/DPI фильтрует WG-паттерн
```

---

## Интерпретация результатов

| Вердикт | Значение | Что делать |
|---------|----------|-----------|
| `p2p_ok` | ✅ AWG P2P работает | Всё в порядке |
| `udp_ok_wg_blocked` | ⚠️ UDP проходит, WG блокируется | Менять H1-H4 параметры, порт |
| `awg_fingerprint_blocked` | ⚠️ Конкретные H1-H4 заблокированы | Сгенерировать новые H-параметры |
| `udp_blocked` | ❌ UDP полностью заблокирован | Нужен relay или TCP-туннель |
| `relay_only` | 🟡 Работает только через relay | Настроить relay в основном профиле |

---

## Конфиг probe.json

После `--init` создаётся файл с вашими AWG-параметрами:

```json
{
  "probe_id": "probe-my-test-1234",
  "mqtt_broker": "tcp://broker.emqx.io:1883",
  "mqtt_topic": "natbypass/probe/probe-my-test-1234",
  "stun_servers": [
    "stun.l.google.com:19302",
    "stun1.l.google.com:3478",
    "stun.cloudflare.com:3478"
  ],
  "awg": {
    "jc": 4, "jmin": 36, "jmax": 77,
    "s1": 37, "s2": 42,
    "h1": 1937135702, "h2": 3731249073,
    "h3": 764002035, "h4": 3695536600,
    "random_trailers": true,
    "disable_cookies": true
  },
  "test_duration_sec": 300
}
```

Вы можете вручную отредактировать AWG-параметры (`h1`–`h4`, `jc` и т.д.) для тестирования разных конфигураций обфускации.

---

## Ключи WireGuard

При первом запуске утилита **автоматически генерирует ключевую пару WireGuard** и сохраняет её в файл `probe-<hostname>.key` рядом с exe. Этот файл содержит приватный ключ — **не передавайте его другим участникам**.

Участники обмениваются **только публичными ключами** через MQTT при обнаружении.

---

## Требования

- **Windows**: требуются права администратора для некоторых сетевых операций (иначе AWG handshake-тест будет пропущен)
- **Linux**: запуск под root рекомендуется
- **Порт UDP 19876** должен быть доступен входящих соединений (можно изменить через `--port`)
- Доступ к публичному MQTT брокеру `broker.emqx.io:1883` (или замените на свой в `probe.json`)

---

## Передача отчётов разработчику

Соберите JSON-отчёты со всех узлов и передайте одним архивом:

```bash
# на каждом узле
natbypass-probe --config probe.json --label "РФ/Ростелеком" --country RU --out report-ru.json
```

Каждый `report-*.json` содержит:
- NAT-тип и STUN-адрес узла
- Результат каждого теста (raw UDP, AWG, TCP, DPI)
- Вердикт по каждой паре с диагностическими заметками

Эти данные позволяют точно определить причину блокировки и предложить обходное решение.