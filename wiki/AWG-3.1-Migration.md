# Миграция на AmneziaWG 3.1

## 🛡️ Почему нужна миграция?

Летом 2026 ТСПУ Роскомнадзора в России начал использовать AI-анализ поведения соединений целиком (корреляция таймингов, размеров пакетов, энтропии и распределения flow). 

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
3. Выберите пресет **🔒 AWG 3.1 Strict (РФ / Китай / Иран)**.
4. Нажмите кнопку **💾 Применить и перезапустить**.
5. Экспортируйте новый конфиг или покажите QR-код для телефона.

### Способ 3: Через CLI-команды

```bash
# 1. Генерация готового конфига AWG 3.1
natbypass-cli awg generate --preset awg31_strict --output /etc/natbypass/awg31.conf

# 2. Настройка параметров
natbypass-cli config set wireguard.awg_version "3.1"
natbypass-cli config set wireguard.awg_preset "awg31_strict"
natbypass-cli config set wireguard.header_protection_key "$(openssl rand -hex 32)"
natbypass-cli config set network.preferred_port 443

# 3. Перезапуск службы
natbypass-cli service restart

# 4. Проверка статуса
natbypass-cli status
```

---

## ⚙️ Пресеты AmneziaWG 3.1

| Пресет | Версия | Описание | Применение |
|---|---|---|---|
| **`awg31_strict`** | **3.1** | Header Protection + Random Trailers + Disable Cookies + Content Padding (0-100B) + CPS packets | **РФ, Китай, Иран (ТСПУ)** |
| **`awg31_balanced`** | **3.1** | Header Protection + Random Trailers + Cookies + Content Padding (0-50B) | Для всех остальных сетей |
| **`anti_tspu`** | **2.0** | Нестандартный тюнинг параметров 2.0 (Jc=5, S2=100, случайные H1..H4) | Совместимость с AWG 2.0 |
| **`awg20_legacy`** | **2.0** | Стандартный WireGuard + AWG 2.0 мусорные пакеты (Jc=4, S1=48, S2=32) | Старые клиенты |

---

## ⚠️ Важное предупреждение о совместимости

> [!WARNING]
> Узлы с **AWG 3.1** не могут соединяться напрямую по WireGuard с узлами на **AWG 2.0** из-за несовместимости структуры пакетов Header Protection.
> Рекомендуется обновлять все связанные устройства одновременно.

---

## 🔄 Откат на AWG 2.0 (Rollback)

Если на определенных устройствах требуется вернуться на режим совместимости AWG 2.0:

```bash
natbypass-cli config set wireguard.awg_version "2.0"
natbypass-cli config set wireguard.awg_preset "awg20_legacy"
natbypass-cli service restart
```