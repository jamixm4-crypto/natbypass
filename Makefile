# ============================================================
# NatBypass — Makefile для кросс-компиляции
# ============================================================

APP      := natbypass
MODULE   := github.com/natbypass/natbypass
CMD_CLI  := ./cmd/natbypass-cli
CMD_GUI  := ./cmd/natbypass-gui
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "release")
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")

LDFLAGS  := -s -w \
            -X $(MODULE)/cmd/natbypass.Version=$(VERSION) \
            -X $(MODULE)/cmd/natbypass.Commit=$(COMMIT) \
            -X $(MODULE)/cmd/natbypass.BuildDate=$(DATE)

GOFLAGS  := CGO_ENABLED=0
GOBUILD  := go build -trimpath -ldflags="$(LDFLAGS)"
DIST     := dist
BIN      := bin

.PHONY: all clean deps tidy fmt vet test \
        windows-gui linux-cli router-mips router-mipsle router-arm64 \
        android-arm64 android-aar android-apk \
        windows-amd64 release help

all: deps linux-cli router-mips router-mipsle router-arm64 android-arm64 windows-amd64

# Сборка Windows GUI (Wails)
windows-gui:
	@echo ">> Сборка Windows GUI (Wails)..."
	@mkdir -p $(DIST)
	cd cmd/natbypass-gui && wails build -o natbypass-gui.exe

# Сборка CLI версии для Linux
linux-cli:
	@echo ">> Сборка CLI версии для Linux..."
	@mkdir -p $(BIN) $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BIN)/natbypass-cli $(CMD_CLI)
	cp $(BIN)/natbypass-cli $(DIST)/$(APP)-linux-amd64 2>/dev/null || true

# Сборка под роутеры MIPS (Big Endian)
router-mips:
	@echo ">> Сборка под MIPS (Big Endian)..."
	@mkdir -p $(BIN) $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=mips GOMIPS=softfloat $(GOBUILD) -o $(BIN)/natbypass-mips $(CMD_CLI)
	cp $(BIN)/natbypass-mips $(DIST)/$(APP)-linux-mips 2>/dev/null || true

# Сборка под роутеры MIPSLE (Keenetic Start/Mini, Xiaomi)
router-mipsle:
	@echo ">> Сборка под MIPSLE (Keenetic)..."
	@mkdir -p $(BIN) $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOBUILD) -o $(BIN)/natbypass-mipsle $(CMD_CLI)
	cp $(BIN)/natbypass-mipsle $(DIST)/$(APP)-linux-mipsle 2>/dev/null || true

# Сборка под роутеры ARM64 (Keenetic Ultra/Giga, RPi)
router-arm64:
	@echo ">> Сборка под ARM64..."
	@mkdir -p $(BIN) $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BIN)/natbypass-arm64 $(CMD_CLI)
	cp $(BIN)/natbypass-arm64 $(DIST)/$(APP)-linux-arm64 2>/dev/null || true

# Сборка под Android
android-arm64:
	@echo ">> Сборка бинарника под Android ARM64 (Termux/ADB/Root)..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=android GOARCH=arm64 $(GOBUILD) -o $(DIST)/$(APP)-android-arm64 $(CMD_CLI)

android-aar:
	@echo ">> Сборка Android AAR библиотеки (Gomobile bind)..."
	@mkdir -p $(DIST)
	gomobile bind -target=android/arm64,android/arm,android/amd64 -o $(DIST)/$(APP).aar ./pkg/mobile

android-apk:
	@echo ">> Сборка Android APK пакета (Gomobile build)..."
	@mkdir -p $(DIST)
	gomobile build -target=android/arm64 -o $(DIST)/$(APP).apk ./cmd/natbypass-cli

windows-amd64:
	@echo ">> Сборка Windows x64..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(DIST)/$(APP)-windows-amd64.exe $(CMD_CLI)

deps:
	@echo ">> Загрузка зависимостей..."
	go mod download

tidy:
	@echo ">> go mod tidy..."
	go mod tidy

clean:
	@echo ">> Очистка..."
	rm -rf $(DIST) $(BIN)

help:
	@echo "NatBypass Makefile targets:"
	@echo "  make windows-gui    - Сборка Windows GUI (Wails)"
	@echo "  make linux-cli      - Сборка CLI версии для Linux"
	@echo "  make router-mips    - Сборка под роутеры MIPS"
	@echo "  make router-mipsle  - Сборка под роутеры MIPSLE"
	@echo "  make router-arm64   - Сборка под роутеры ARM64"
	@echo "  make android-arm64  - Сборка бинарника для Android (Termux/ADB)"
	@echo "  make android-aar    - Сборка AAR библиотеки для Android Studio"
	@echo "  make android-apk    - Сборка APK пакета (gomobile)"
	@echo "  make all            - Сборка под все платформы"