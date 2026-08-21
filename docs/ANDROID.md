# 📱 Инструкция по настройке для Android

NatBypass на Android позволяет вашему смартфону или планшету оставаться на связи с домашней сетью и роутером из любой точки мира через мобильный 4G/5G интернет (даже за жестким CGNAT оператора).

---

## Вариант 1: Запуск через Termux (Без Root прав)

Самый быстрый способ запустить NatBypass на любом современном Android смартфоне:

1. Установите [Termux из F-Droid](https://f-droid.org/packages/com.termux/).
2. Откройте Termux и выполните команды:
   ```bash
   pkg update && pkg install -y wget curl

   # 1. Скачиваем бинарник для Android ARM64
   wget -O natbypass https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-android-arm64
   chmod +x natbypass

   # 2. Скачиваем файл конфигурации
   wget -O config.yaml https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/config.yaml.example
   ```
3. Отредактируйте `config.yaml` (введите данные Telegram или MQTT):
   ```bash
   nano config.yaml
   ```
4. Запустите NatBypass:
   ```bash
   ./natbypass start --config config.yaml
   ```
5. Откройте браузер на смартфоне и перейдите по адресу: **`http://localhost:8080`**.
   * Вы увидите полноценную панель управления NatBypass со всеми вашими подключенными домашними устройствами и роутерами!

---

## Вариант 2: Подключение AmneziaWG / WireGuard на Android
 
1. В веб-панели `http://localhost:8080` перейдите на вкладку **«🛡️ AmneziaWG 2.0»** (для обхода DPI) или **«🔒 WireGuard»**.
2. Нажмите **«📥 Скачать .conf»** или скопируйте сгенерированную конфигурацию.
3. Установите приложение **AmneziaWG** (или **WireGuard**) из Google Play / F-Droid.
4. В приложении нажмите **«+» -> «Импорт из файла или архива»** и выберите скачанный `.conf` файл.
5. Включите туннель. Теперь ваш телефон имеет прямой защищенный доступ к вашему роутеру и ПК по локальным адресам `10.200.0.x`!
 
---
 
## 📱 Быстрое подключение через QR-код
 
В веб-интерфейсе NatBypass на ПК на вкладке **«🚀 Быстрый старт»** (Шаг 4) отображается **QR-код**: отсканируйте его камерой телефона, чтобы мгновенно открыть ссылку на скачивание и параметры вашей сети.