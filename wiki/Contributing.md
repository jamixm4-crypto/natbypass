# Участие в разработке NatBypass (Contributing Guide)

Мы приветствуем вклад сообщества в развитие NatBypass!

---

## 🛠️ Сборка из исходников

Для сборки требуется **Go 1.24+**:

```bash
git clone https://github.com/jamixm4-crypto/natbypass.git
cd natbypass

# Запуск тестов
make test

# Сборка под вашу платформу
make windows-gui     # Нативный GUI для Windows
make linux-amd64     # Linux демон
make router-mipsle   # Keenetic роутеры
```

---

## 📋 Стандарты кодовой базы

1. **Zero CGO:** Проект компилируется со строгим `CGO_ENABLED=0` для поддержки роутеров с MIPS/ARM архитектурами.
2. **Безопасность памяти:** Все TUN-буферы выделяются через `sync.Pool`.
3. **Форматирование:** Перед отправкой Pull Request запустите `go fmt ./...` и `go vet ./...`.
4. **Кодекс поведения:** Ознакомьтесь с [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).
