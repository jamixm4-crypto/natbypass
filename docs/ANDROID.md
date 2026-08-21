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

## Вариант 2: Подключение WireGuard на Android

1. В веб-панели `http://localhost:8080` (или в Termux командой `curl -s http://localhost:8080/api/wg/config`) скопируйте сгенерированный конфигурационный файл.
2. Установите официальное приложение **WireGuard** из Google Play / F-Droid.
3. Нажмите кнопку **«+» -> «Создать с нуля»** (или импортируйте текст).
4. Вставьте конфигурацию, задайте имя туннеля (например, `HomeMesh`) и нажмите **Сохранить**.
5. Включите туннель. Теперь ваш телефон имеет прямой доступ к вашему роутеру и ПК по локальным адресам `10.200.0.x`!