# ============================================================
# NatBypass — Professional Cross-Platform Makefile (Pure Go, Zero CGO)
# ============================================================

APP      := natbypass
MODULE   := github.com/natbypass/natbypass
CMD_MAIN := ./cmd/natbypass
CMD_CLI  := ./cmd/natbypass-cli
CMD_GUI  := ./cmd/natbypass-gui
CMD_PROBE:= ./cmd/natbypass-probe
DIST     := dist
BIN      := bin

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.9.506-beta.1")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "release")
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")

LDFLAGS  := -s -w \
            -X main.Version=$(VERSION) \
            -X main.Commit=$(COMMIT) \
            -X main.BuildDate=$(DATE)

GOFLAGS  := CGO_ENABLED=0
GOBUILD  := go build -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all clean deps tidy fmt vet test govulncheck \
        windows-all windows-gui windows-cli windows-service \
        linux-amd64 linux-arm64 \
        router-mipsle router-mips router-armv7 \
        help

all: windows-all linux-amd64 linux-arm64 router-mipsle router-mips router-armv7

# Windows Builds (Pure Go Native Win32 / Service)
windows-gui:
	@echo ">> Building Windows Native GUI (Win32, Zero CGO)..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=windows GOARCH=amd64 $(GOBUILD) -H=windowsgui -o $(DIST)/NatBypass-GUI.exe $(CMD_GUI)

windows-service:
	@echo ">> Building Windows Background Service / Tray Daemon..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=windows GOARCH=amd64 $(GOBUILD) -H=windowsgui -o $(DIST)/NatBypass.exe $(CMD_MAIN)

windows-cli:
	@echo ">> Building Windows CLI..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(DIST)/natbypass-cli.exe $(CMD_CLI)

windows-all: windows-gui windows-service windows-cli

# Linux Server & Desktop
linux-amd64:
	@echo ">> Building Linux x86_64 Daemon..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(DIST)/natbypass-linux-amd64 $(CMD_MAIN)

linux-arm64:
	@echo ">> Building Linux ARM64 Daemon (Raspberry Pi / VPS)..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(DIST)/natbypass-linux-arm64 $(CMD_MAIN)

# Embedded Routers (Keenetic, OpenWrt, Entware)
router-mipsle:
	@echo ">> Building Keenetic MIPSle Softfloat (Start, City, Air, Extra, Speedster)..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOBUILD) -o $(DIST)/natbypass-keenetic-mipsle $(CMD_MAIN)

router-mips:
	@echo ">> Building OpenWrt MIPS Big-Endian Softfloat..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=mips GOMIPS=softfloat $(GOBUILD) -o $(DIST)/natbypass-router-mips $(CMD_MAIN)

router-armv7:
	@echo ">> Building OpenWrt / Keenetic ARMv7 32-bit (Cortex-A7/A9)..."
	@mkdir -p $(DIST)
	$(GOFLAGS) GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $(DIST)/natbypass-router-armv7 $(CMD_MAIN)

# Quality & Testing
deps:
	@echo ">> Downloading Go dependencies..."
	go mod download

tidy:
	@echo ">> Tidying Go modules..."
	go mod tidy

fmt:
	@echo ">> Formatting source files..."
	go fmt ./...

vet:
	@echo ">> Running go vet..."
	go vet ./...

test:
	@echo ">> Running automated test suite..."
	go test -v -timeout 180s ./internal/...

clean:
	@echo ">> Cleaning build outputs..."
	rm -rf $(DIST) $(BIN)

help:
	@echo "NatBypass Makefile targets:"
	@echo "  make windows-gui    - Windows Native GUI (Win32, no CGO, 15MB RAM)"
	@echo "  make windows-service- Windows Background Service / Tray Daemon"
	@echo "  make windows-cli    - Windows CLI binary"
	@echo "  make windows-all    - All Windows binaries"
	@echo "  make linux-amd64    - Linux x86_64 daemon"
	@echo "  make linux-arm64    - Linux ARM64 daemon"
	@echo "  make router-mipsle  - Keenetic / MIPSle router binary"
	@echo "  make router-mips    - OpenWrt / MIPS (big-endian) router binary"
	@echo "  make router-armv7   - OpenWrt / ARMv7 router binary"
	@echo "  make all            - Build all platform targets"
	@echo "  make test           - Run full unit test suite"
	@echo "  make clean          - Remove all build artifacts"
