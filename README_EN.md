# NatBypass

**P2P Mesh VPN & DPI Bypass** — direct socket-to-socket mesh connectivity for computers, servers, phones, and routers across all types of NAT/CGNAT without requiring dedicated relay servers.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-supported-platforms)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

## 📚 [Official Knowledge Base (Wiki)](https://github.com/jamixm4-crypto/natbypass/wiki)

Comprehensive documentation and step-by-step guides are available in our [**NatBypass Wiki**](https://github.com/jamixm4-crypto/natbypass/wiki):
* 🚀 [**Quick Start in 5 minutes**](https://github.com/jamixm4-crypto/natbypass/wiki/Quick-Start) — connect your first P2P pair of devices without console commands.
* 🛡️ [**Censorship Bypass (AmneziaWG 3.1 & 2.0)**](https://github.com/jamixm4-crypto/natbypass/wiki/AmneziaWG-DPI-Bypass) — tuning Jc, Jmin, Jmax, S1, S2, H1..H4 parameters against deep packet inspection (DPI / TSPU).
* 🌐 [**Keenetic Routers (Entware)**](https://github.com/jamixm4-crypto/natbypass/wiki/Keenetic-Routers) & [**OpenWrt**](https://github.com/jamixm4-crypto/natbypass/wiki/OpenWrt-Routers) — 1-command installation and daemon service setup.
* 📱 [**Android Guide**](https://github.com/jamixm4-crypto/natbypass/wiki/Android-Setup) — connect via QR code, interactive on-screen QR display, and native VpnService.
* 🪟 [**Windows Guide**](https://github.com/jamixm4-crypto/natbypass/wiki/Windows-Guide) — native GUI, system tray, Wintun driver, and server background mode.
* 🔧 [**Diagnostics and Troubleshooting**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — universal diagnostic scripts and end-to-end ICMP ping verification.

---

## ✨ Key Features

- ⚡ **Pure P2P UDP Mesh:** Direct datagram communication between peers via STUN UDP Hole Punching without renting VPS servers.
- 🛡️ **AmneziaWG 3.1 & 2.0:** Built-in Deep Packet Inspection (DPI) protection with custom obfuscated headers (H1..H4), junk packets (Jc, Jmin, Jmax), and content padding randomization (S1, S2).
- 📡 **Multi-Channel Signaling:** Peer discovery and endpoint exchange via Telegram Bot API, MQTT, Cloudflare DNS TXT, and HTTP Webhooks with NaCl/Box E2E encryption (X25519 + XSalsa20-Poly1305).
- 🔄 **Hot Dynamic Configuration:** Instant room/topic switching, AWG profile reload, and Virtual IP updates without restarting the daemon.
- 🔍 **Automated Diagnostic Suite:** Built-in dynamic peer discovery and L3 ICMP testing across all platforms.
- 📱 **Android All-in-One:** Native VpnService in pure Go, on-screen interactive QR sharing, and Quick Settings Tile.
- 🪟 **Native Windows GUI:** Ultra-lightweight non-CGO interface, system tray integration, supporting Windows 10/11 and Server editions.
- 🔐 **Isolated Mesh Profiles:** Manage multiple isolated mesh rooms ("Home", "Office", "Servers") with seamless on-the-fly switching.

---

## 🔍 Universal Diagnostic Tools

NatBypass includes a fully **dynamic diagnostic suite** that queries the local daemon, discovers all connected mesh nodes, tests end-to-end L3 ICMP ping to each peer with zero packet loss verification, and audits network stack health, STUN endpoints, NAT classification, and routing tables.

### 🐧 Linux / KeeneticOS / OpenWrt
Run in one command (no extra dependencies required):
```bash
wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh
```
*(or via curl: `curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh`)*

If `natbypass` binary is already installed in your path:
```bash
natbypass diag
```

### 🪟 Windows (PowerShell)
Run the diagnostic script as Administrator:
```powershell
irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex
```
*(or via CLI: `.\NatBypass.exe diag`)*

---

## 🏗️ P2P Network Architecture

```
              ┌──────────────────────────────────────────────────────────┐
              │             Signaling Channels (E2EE)                    │
              │  [Telegram Bot] ── [MQTT Broker] ── [Cloudflare DNS/Web] │
              └────────▲────────────────────────────────────────▲────────┘
                       │           (encrypted beacons)          │
                       │                                        │
         ┌─────────────┴──────────┐                  ┌──────────┴─────────────┐
         │    Device A            │                  │    Device B            │
         │  STUN Discovery        │                  │  STUN Discovery        │
         │  Windows App (Wintun)  │                  │  Keenetic / Linux / Android
         │  VIP: 100.64.200.1     │                  │  VIP: 100.64.200.2     │
         └─────────────┬──────────┘                  └──────────┬─────────────┘
                       │                                        │
                       └─────────── Direct UDP Socket ──────────┘
                                 (P2P Mesh / AWG 3.1)
```

---

## 📦 Supported Platforms

| Platform | Architecture | Release Binary | Description |
|---|---|---|---|
| **Windows** | amd64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Windows 10/11 / Server (Desktop GUI + Tray + Wintun) |
| **Android** | arm64 / arm / x64 | [NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR Scanner + Screen QR) |
| **Linux** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **MIPS Routers** | mips (Big Endian) | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest) | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **MIPSLE Routers**| mipsle (Little Endian)| [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest)| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Quick Start

### Windows (10/11 & Windows Server)
1. Download [**NatBypass.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. Run as Administrator to initialize the Wintun adapter.
3. The application will open in a native GUI window.

### Linux / Keenetic / OpenWrt (1-Command Install)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(or via wget: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Web Management UI will be accessible at: `http://<DEVICE_IP>:8080`.

---

## 🛡️ AmneziaWG 3.1 & 2.0 (DPI Obfuscation)

NatBypass features **AmneziaWG 3.1** — advanced WireGuard protocol obfuscation designed to bypass Deep Packet Inspection (DPI / TSPU) censorship systems.

### ⚙️ Available Protocol Presets

| Preset | Version | Description | Target Use Case |
|---|---|---|---|
| **`awg31_strict`** | **AWG 3.1** | Header Protection + Random Trailers + Disable Cookies + Content Padding (0-100B) + CPS Packets + Random Timers | **Maximum DPI / TSPU Censorship Bypass** |
| **`awg31_balanced`** | **AWG 3.1** | Header Protection + Random Trailers + Cookies + Content Padding (0-50B) + Standard Jitter | Default recommended for all networks |
| **`anti_tspu`** | **AWG 2.0** | Custom 2.0 parameter tuning (Jc=5, S2=100, randomized H1..H4) | Enhanced compatibility |
| **`awg20_legacy`** | **AWG 2.0** | Standard WireGuard + AWG 2.0 junk packets (Jc=4, S1=48, S2=32) | Legacy clients |

---

## 🗺️ Roadmap

- 🧪 **Fallback Protocol Evaluation & Benchmarking:** Currently testing, evaluating, and determining the most reliable and censorship-resistant reserve/fallback transport protocols to ensure zero downtime even under complete UDP filtering by ISPs.
- 🧩 **Adaptive Transport Controller:** Seamless auto-switching between Direct P2P UDP, AmneziaWG, and reserve fallback tunnels based on real-time RTT, jitter, and packet loss metrics.

---

## 📄 License

This project is licensed under the open-source [MIT License](LICENSE).