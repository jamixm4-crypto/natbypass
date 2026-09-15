# NatBypass

**P2P Mesh VPN & DPI Bypass** — direct socket-to-socket mesh connectivity for computers, servers, phones, and routers across all types of NAT/CGNAT without requiring dedicated relay servers.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-supported-platforms)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

## 📚 [Official Knowledge Base (Wiki)](https://github.com/jamixm4-crypto/natbypass/wiki)

Comprehensive documentation and step-by-step guides are available in our [**NatBypass Wiki**](https://github.com/jamixm4-crypto/natbypass/wiki):
* 🚀 [**Quick Start in 5 minutes**](https://github.com/jamixm4-crypto/natbypass/wiki/Quick-Start) — connect your first P2P pair of devices without console commands.
* 🛡️ [**Censorship Bypass (AmneziaWG)**](https://github.com/jamixm4-crypto/natbypass/wiki/AmneziaWG-DPI-Bypass) — tuning Jc, Jmin, Jmax, S1, S2, H1..H4 parameters against deep packet inspection (DPI / TSPU).
* 🌐 [**Keenetic Routers (Entware)**](https://github.com/jamixm4-crypto/natbypass/wiki/Keenetic-Routers) & [**OpenWrt**](https://github.com/jamixm4-crypto/natbypass/wiki/OpenWrt-Routers) — 1-command installation and daemon service setup.
* 📱 [**Android Guide**](https://github.com/jamixm4-crypto/natbypass/wiki/Android-Setup) — connect via QR code, interactive on-screen QR display, and native VpnService.
* 🪟 [**Windows Guide**](https://github.com/jamixm4-crypto/natbypass/wiki/Windows-Guide) — native GUI, system tray, Wintun driver, and server background mode.
* 🧪 [**Updating & Beta Channel**](https://github.com/jamixm4-crypto/natbypass/wiki/Updating-and-Beta-Versions) — 1-click upgrade instructions for Windows, Linux, routers, and Android.
* 🔧 [**Diagnostics and Troubleshooting**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — universal diagnostic scripts and end-to-end ICMP ping verification.
* ⚡ [**Multi-Tier NAT Traversal**](docs/NAT_TRAVERSAL.md) — 5-tier CGNAT bypass, ⚡ Coordinator and 🛡️ Relay badge guide.

---

## ✨ Key Features

- ⚡ **Pure P2P UDP Mesh:** Direct datagram communication between peers via STUN UDP Hole Punching without renting VPS servers.
- 🛡️ **AmneziaWG Obfuscation:** Built-in Deep Packet Inspection (DPI) protection with custom obfuscated headers (H1..H4), junk packets (Jc, Jmin, Jmax), header protection, and content padding randomization (S1, S2).
- 🌐 **Internet Exit Node Gateway:** Any node (Keenetic, Linux server, Windows PC, or Android) can act as a secure Internet Gateway with full DNS leak protection (`1.1.1.1`, `8.8.8.8`) and physical gateway bypass routing.
- 📡 **Multi-Channel Signaling:** Peer discovery and endpoint exchange via Telegram Bot API, MQTT, Cloudflare DNS TXT, and HTTP Webhooks with NaCl/Box E2E encryption (X25519 + XSalsa20-Poly1305).
- 🚀 **Embedded Router Optimizations:** Zero CGO pure Go runtime, `sync.Pool` 64KB packet buffers, GC memory bounding to 48MB RAM, asynchronous diode logging — running reliably on 64–128MB RAM MIPS/ARM routers (Keenetic, OpenWrt).
- 🔄 **Hot Dynamic Configuration:** Instant room/topic switching, obfuscation profile reload, and Virtual IP updates without restarting the daemon.
- 🔍 **Automated Diagnostic Suite:** Built-in dynamic peer discovery and L3 ICMP testing across all platforms.
- 📱 **Android 10–15 All-in-One:** Native asynchronous VpnService (`systemExempted`), on-screen interactive QR sharing, and Quick Settings Tile.
- 🪟 **Native Windows GUI:** Ultra-lightweight non-CGO interface (15–25MB RAM, no Electron/WebView2 bloat), system tray integration, supporting Windows 10/11 and Server editions.
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
                                 (P2P Mesh / AmneziaWG)
```

---

## ⚡ How Multi-Tier NAT Traversal Works

NatBypass features an autonomous **5-tier NAT Traversal architecture** designed to connect mobile clients behind symmetric cellular CGNAT (LTE/5G) directly or via mesh relays **without requiring dedicated servers**:

| Tier | Technology | Description |
|---|---|---|
| **Tier 1** | **IPv6 Dual-Stack P2P** | Dual-stack AAAA STUN discovery and direct socket-to-socket IPv6 data path bypassing IPv4 CGNAT. |
| **Tier 2** | **DPI Drop Detection** | Detects deep packet inspection drop (10 unacked probes) and temporarily escalates to `awg31_strict` for 10 minutes. |
| **Tier 3** | **Leader-Coordinated Punch** | Millisecond-precision synchronized port opening orchestrated by a Cone NAT mesh coordinator. |
| **Tier 4** | **ASN-Aware Port Prediction** | Selective port delta prediction (+2, +4) using cellular ASN rules; random pools are skipped to save battery. |
| **Tier 5** | **Peer-as-Relay** | Transparent E2EE transit through trusted home router/server nodes within daily quotas (5 GB/day default). |

### 🎯 WebUI & Android Badges Explained:
- ⚡ **Coordinator** (`coordinator_capable`) — Node with Full-Cone NAT or public IP. Coordinates synchronized bilateral port punches between mobile peers.
- 🛡️ **Relay** (`relay_capable`) — Node (Keenetic router, Linux server, or PC) with `enable_relay_server: true`. Relays encrypted traffic when direct UDP is completely blocked by carrier CGNAT. *(Android devices are automatically excluded on cellular data or low battery).*
- 🌐 **Exit Node Gateway** (`is_exit_node`) — Node acting as a secure Internet Gateway.
- 🏠 **Subnet Route** (`advertised_routes`) — Node advertising access to its LAN (e.g., `192.168.1.0/24`).

👉 Comprehensive documentation: [**docs/NAT_TRAVERSAL.md**](docs/NAT_TRAVERSAL.md).

## 📦 Supported Platforms

| Platform | Architecture | Release Binary | Description |
|---|---|---|---|
| **Windows (WebUI)** | amd64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11** (WebUI browser control panel `http://localhost:8080` + Tray + Wintun) |
| **Windows (GUI)** | amd64 | [NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11** & **Windows Server (2016/2019/2022/2025)** (Pure native Win32 GDI GUI, no browser required, 15 MB RAM + Tray) |
| **Windows (CLI)** | amd64 | [natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11 / Server** (Headless CLI for automation, services, and background tasks) |
| **Android** | arm64 / arm / x64 | [NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (VpnService + QR Scanner + Screen QR) |
| **Linux** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **MIPS Routers** | mips (Big Endian) | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest) | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **MIPSLE Routers**| mipsle (Little Endian)| [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest)| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Quick Start

### Windows
* **Windows 10 / 11 (WebUI Version):**
  1. Download [**NatBypass.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
  2. Run as Administrator. Browser management UI will open at `http://localhost:8080`.
* **Windows 10 / 11 & Windows Server (Native GUI Version):**
  1. Download [**NatBypass-GUI.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
  2. Run as Administrator. Opens a lightweight native Win32 window (does not require WebView2/browser/Electron, 15–25 MB RAM, ideal for Windows Server).
* **Windows Server / Headless (CLI):**
  1. Download [**natbypass-cli.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest). Run: `.\natbypass-cli.exe -c config.yaml`.

### Linux / Keenetic / OpenWrt (1-Command Install)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(or via wget: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

Web Management UI will be accessible at: `http://<DEVICE_IP>:8080`.

---

## 🛡️ AmneziaWG (DPI Obfuscation)

NatBypass features **AmneziaWG** — WireGuard protocol obfuscation designed to bypass Deep Packet Inspection (DPI / TSPU) censorship systems.

### ⚙️ Available Protocol Presets

| Preset | Description | Target Use Case |
|---|---|---|
| **`Strict`** | Header Protection + Random Trailers + Disable Cookies + Content Padding + CPS Packets + Random Timers | **Maximum DPI / TSPU Censorship Bypass** |
| **`Balanced`** | Header Protection + Random Trailers + Cookies + Content Padding + Standard Jitter | Default recommended for all networks |
| **`Anti-TSPU`** | Custom parameter tuning (Jc=5, S2=100, randomized H1..H4) | Enhanced compatibility |
| **`Legacy`** | Standard WireGuard + junk packets (Jc=4, S1=48, S2=32) | Legacy clients |

---

## 🌐 Internet Exit Node Gateway

NatBypass allows routing full internet traffic through any selected mesh node (Keenetic router, Linux server, or Windows PC):
1. **Automated Routing:** The client receives a `0.0.0.0/0` default route while preserving peer-to-peer mesh connectivity. Critical `/32` routes for signaling brokers and STUN endpoints are added via the physical default gateway.
2. **DNS Leak Prevention:** All DNS queries are redirected to secure resolvers (`1.1.1.1`, `8.8.8.8`) via the encrypted tunnel, bypassing local ISP eavesdropping and filtering.
3. **1-Click Control:** Enable or disable internet gateway routing via WebUI, Windows GUI, or Android app.

---

## 🧪 Upgrading to Beta / Pre-release Builds

Get the latest performance optimizations, bug fixes, and protocol improvements across all clients:

### 📱 Android
1. Open App **Settings** -> **Updates**.
2. Toggle the **🧪 Тестовые сборки (Beta)** switch.
3. Click **"Скачать и обновить"** (Download & Update) to fetch the newest APK directly from GitHub.

### 🌐 WebUI (Keenetic, OpenWrt, Linux, Windows)
1. Open WebUI (`http://<DEVICE_IP>:8080`).
2. Click **🔄 Update** in the top navigation bar.
3. Enable **"Тестовые сборки (Beta / Pre-release)"** and click **"Check for updates"**.
4. Click **"Install update"** — the daemon updates and reloads seamlessly without losing peer states.

### 🐧 Linux / Keenetic / OpenWrt (Terminal)
Upgrade in one line:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/update.sh | sh -s -- --beta
```
or via the native binary:
```bash
natbypass update --beta
```

### 🪟 Windows GUI & CLI
- In **NatBypass GUI**, right-click the system tray icon -> **"Check for updates..."**.
- In PowerShell (Run as Administrator):
```powershell
irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/update.ps1 | iex -ArgumentList "-Beta"
```

---

## 🗺️ Roadmap

- 🧪 **Fallback Protocol Evaluation & Benchmarking:** Currently testing, evaluating, and determining the most reliable and censorship-resistant reserve/fallback transport protocols to ensure zero downtime even under complete UDP filtering by ISPs.
- 🧩 **Adaptive Transport Controller:** Seamless auto-switching between Direct P2P UDP, AmneziaWG, and reserve fallback tunnels based on real-time RTT, jitter, and packet loss metrics.

---

## 📄 License

This project is licensed under the open-source [GNU General Public License v3.0 (GPLv3)](LICENSE).