# 🛡️ Инструкция по настройке AmneziaWG 2.0 (AWG) для обхода блокировок DPI

**AmneziaWG (AWG 2.0)** — это современный протокол обфускации трафика WireGuard, специально разработанный для работы в условиях жесткой цензуры и блокировок со стороны ТСПУ / Deep Packet Inspection (DPI).

---

## 🔬 Как AmneziaWG 2.0 обходит DPI

Обычный WireGuard легко распознается системами анализа трафика по характерной структуре первого байта UDP пакета (`0x01` — Handshake Initiation, `0x02` — Handshake Response) и строго фиксированному размеру пакетов (148 байт).

**AmneziaWG 2.0 полностью решает эту проблему:**
1. **Замена заголовков (`H1, H2, H3, H4`):** Вместо стандартных байтов `0x01..0x04` используются уникальные 32-битные случайные числа, известные только вашим устройствам.
2. **Мусорный трафик перед хэндшейком (`Jc, Jmin, Jmax`):** Перед установкой соединения отправляется от 3 до 8 случайных UDP пакетов разного размера, что сбивает с толку сигнатурные анализаторы DPI.
3. **Рандомизация размера хэндшейка (`S1, S2`):** К началу пакетов инициализации и ответа добавляются случайные байты мусора, делая размер пакета уникальным для каждой сессии.

---

## 📥 Как получить AmneziaWG 2.0 конфиг в NatBypass

1. Откройте панель управления **NatBypass** (`http://localhost:8080` или главное окно Windows GUI).
2. Перейдите на вкладку **«🛡️ AmneziaWG 2.0»**.
3. (Опционально) Нажмите **«🎲 Случайные параметры AWG»**, чтобы создать уникальную сигнатуру сети.
4. Нажмите **«📥 Скачать amneziawg-mesh.conf»**.

---

## 📱 Клиенты с поддержкой AmneziaWG 2.0

| ОС / Платформа | Официальный клиент | Инструкция подключения |
|---|---|---|
| 🪟 **Windows** | [AmneziaWG for Windows](https://github.com/amnezia-vpn/amneziawg-windows-client/releases) | Нажмите *«Добавить туннель» -> выберите `amneziawg-mesh.conf`* |
| 📱 **Android** | [AmneziaWG Android (Google Play / GitHub)](https://github.com/amnezia-vpn/amneziawg-android/releases) | Нажмите *«+» -> «Импорт из файла»* |
| 🍏 **iOS / macOS** | [AmneziaWG в App Store](https://apps.apple.com/app/amneziawg/id6478942364) | Импортируйте файл `.conf` или QR-код |
| 🌐 **Keenetic** | Пакет `kmod-amneziawg` / Entware | Настройка через интерфейс AWG |
| 📡 **OpenWrt** | Пакеты `kmod-amneziawg` + `amneziawg-tools` | Поддерживается как нативный протокол `proto 'amneziawg'` |

---

## 📋 Пример конфигурационного файла `amneziawg-mesh.conf`

```ini
[Interface]
PrivateKey = aAAA...=
Address = 10.200.0.2/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 70
S1 = 48
S2 = 32
H1 = 1428571428
H2 = 2147483647
H3 = 857142857
H4 = 1122334455

[Peer]
PublicKey = bBBB...=
Endpoint = 95.165.22.14:41290
AllowedIPs = 10.200.0.1/32
PersistentKeepalive = 25
```