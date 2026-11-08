# Миграция на AmneziaWG 3.1

> [!TIP]
> **В новых версиях NatBypass (v2.0+) протокол AmneziaWG 3.1 Strict и порт 443 включены ПО УМОЛЧАНИЮ**. Никакой ручной настройки в конфигах не требуется — все новые сети создаются с максимальной защитой от ТСПУ.

## 🛡️ Почему нужна миграция со старых версий?

Системы ТСПУ и DPI используют использовать AI-анализ поведения соединений целиком (корреляция таймингов, размеров пакетов, энтропии и распределения flow). 

Старый протокол **AWG 2.0** обфусцирует только статические заголовки, из-за чего обнаруживается поведенческими эвристиками за 2–5 минут активной передачи данных.

**AmneziaWG 3.1** внедряет полный комплекс поведенческой маскировки:
- **Header Protection (ChaCha20)** — шифрование открытых полей `Init`, `Response`, `Cookie`, `Data`
- **Content Padding** — добавление случайных байт к transport payload (0–100 байт)
- **Custom Timings** — рандомизация таймеров Rekey, Timeout, Keepalive в заданных диапазонах
- **Random Trailers** — добавление случайной энтропии в хвост пакетов
- **Disable Cookies** — защита от активного зондирования (active probing)

---

## 🚀 Пошаговая миграция

### Способ 1: Автоматический скрипт (Рекомендуется)

```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/migrate_to_awg31.sh | bash
```

### Способ 2: Через Web UI

1. Откройте панель управления `http://127.0.0.1:8080` (или IP вашего роутера/сервера).
2. Перейдите на вкладку **🛡️ AmneziaWG 3.1**.
3. Выберите пресет **🔒 AWG 3.1 Strict (Максимальное пробитие ТСПУ / DPI)**.
4. Нажмите кнопку **💾 Применить и перезапустить**.
5. Экспортируйте новый конфиг или покажите QR-код для телефона.

### Способ 3: Через конфигурационный файл config.yaml

Отредактируйте `/etc/natbypass/config.yaml` (или `config.yaml` рядом с exe):

```yaml
wireguard:
  enable_amnezia: true
  awg_preset: "awg31_strict"
  # Опционально: кастомный ключ защиты заголовков (32 байта hex)
  # header_protection_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
network:
  preferred_port: 443
```

После изменения перезапустите службу:
* **Linux:** `systemctl restart natbypass`
* **Keenetic:** `/opt/etc/init.d/S99natbypass restart`
* **OpenWrt:** `/etc/init.d/natbypass restart`
* **Windows:** перезапустите приложение или выполните `natbypass-cli.exe service start`

---

## ⚙️ Пресеты AmneziaWG 3.1

| Пресет | Версия | Описание | Применение |
|---|---|---|---|
| **`awg31_strict`** | **3.1** | Header Protection + Random Trailers + Disable Cookies + Content Padding (0-100B) + CPS packets | **Максимальное пробитие ТСПУ / DPI** |
| **`awg31_balanced`** | **3.1** | Header Protection + Random Trailers + Cookies + Content Padding (0-50B) | Для всех остальных сетей |
| **`anti_tspu`** | **2.0** | Нестандартный тюнинг параметров 2.0 (Jc=5, S2=100, случайные H1..H4) | Совместимость с AWG 2.0 |
| **`awg20_legacy`** | **2.0** | Стандартный WireGuard + AWG 2.0 мусорные пакеты (Jc=4, S1=48, S2=32) | Старые клиенты |

---

## ⚠️ Важное предупреждение о совместимости

> [!WARNING]
> Узлы с **AWG 3.1** не могут соединяться напрямую по WireGuard с узлами на **AWG 2.0** из-за несовместимости структуры пакетов Header Protection.
> Рекомендуется обновлять все связанные устройства одновременно.

---

## 🔄 Откат на режим совместимости AWG 2.0 (Rollback)

Если на определенных устройствах требуется вернуться на режим совместимости AWG 2.0, укажите в `config.yaml`:

```yaml
wireguard:
  enable_amnezia: true
  awg_preset: "anti_tspu"
```
И перезапустите службу (`systemctl restart natbypass` или через WebUI).