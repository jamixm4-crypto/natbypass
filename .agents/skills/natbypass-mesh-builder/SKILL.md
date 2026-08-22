---
name: natbypass-mesh-builder
description: >-
  Expert runbook and automated workflows for building, testing, and managing NatBypass P2P Mesh Network nodes.
  Use when compiling for Windows, Linux, routers (Keenetic, OpenWrt, MIPS/ARM), or configuring STUN and multi-channel signaling (MQTT, Telegram, DNS TXT, Webhooks).
---

# NatBypass Mesh Builder & Architecture Skill

## 1. Project Overview & Architecture
NatBypass establishes direct P2P mesh WireGuard and AmneziaWG connections across symmetric and double NATs/CGNATs using decentralized signaling channels and STUN hole punching.

### Key Signaling Mechanisms
- **MQTT (Primary High-Speed Bus)**: QoS 0 fire-and-forget peer discovery on public or private brokers (`broker.emqx.io:1883`, `broker.hivemq.com`, `mqtt.eclipseprojects.io`).
- **Telegram Bot API (Fallback / Broadcast)**: `sendMessage` with Base64 payloads and negative offset multi-node update polling (`offset=-25`).
- **Cloudflare DNS TXT / Webhooks**: Additional asynchronous backup discovery.

---

## 2. Compilation Workflows

### Windows Native GUI Build
```powershell
$env:GOROOT="e:\qwen\fnat\soft\go"
$env:GOPATH="e:\qwen\fnat\soft\gopath"
$env:GOCACHE="e:\qwen\fnat\soft\gocache"
$env:GOOS="windows"
$env:GOARCH="amd64"

# Generate embedded PE icon & manifest if app.ico changed
& "e:\qwen\fnat\soft\gopath\bin\rsrc.exe" -ico "app.ico" -arch "amd64" -o "e:\qwen\fnat\cmd\natbypass-gui\rsrc_windows_amd64.syso"

# Build lightweight Windows GUI binary (no console window)
& "e:\qwen\fnat\soft\go\bin\go.exe" build -trimpath -ldflags="-s -w -H=windowsgui" -o "dist/NatBypass.exe" ./cmd/natbypass-gui
```

### Linux & Router Targets (Keenetic / OpenWrt / Entware)
```bash
# Linux x86_64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/natbypass-linux-amd64 ./cmd/natbypass

# Keenetic / OpenWrt (MIPS 32-bit Little Endian)
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags="-s -w" -o dist/natbypass-keenetic-mipsle ./cmd/natbypass

# OpenWrt / Routers (ARMv7)
GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="-s -w" -o dist/natbypass-openwrt-armv7 ./cmd/natbypass

# Raspberry Pi / Servers (ARM64)
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/natbypass-linux-arm64 ./cmd/natbypass
```

---

## 3. Best Practices
1. **Parallel Signaling**: Always maintain MQTT as the fast transport while broadcasting status to Telegram.
2. **Context Isolation**: Give each network broadcast goroutine a dedicated 10-second timeout context.
3. **No External Framework Bloat**: Pure Go userspace cryptographic and network primitives to preserve router flash storage compatibility.
