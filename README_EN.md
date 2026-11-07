# NatBypass

**P2P Mesh VPN & DPI Bypass** — direct socket-to-socket mesh connectivity for computers, servers, phones, and routers across all types of NAT/CGNAT without requiring dedicated relay servers.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-supported-platforms)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

> [!NOTE]
> ### 🛡️ Project Purpose & Anti-Malware Disclaimer
> **NatBypass** is an open-source, decentralized P2P Mesh VPN engineered solely for personal privacy, securely inter-connecting personal and home devices (Keenetic/OpenWrt routers, Android phones, home PCs, NAS servers) across carrier-grade NAT, and resisting DPI censorship.
> 
> * **Not a Pentesting Tool:** NatBypass is **NOT** a penetration testing tool, port scanner, backdoor, or remote access Trojan (RAT). It has **NO affiliation or relation** to legacy port-forwarding tools (such as `cw1997/NATBypass`, `lcx`, etc.).
> * **End-to-End Encryption (E2EE):** All user traffic is strongly encrypted (Noise_IK / ChaCha20-Poly1305 / NaCl Box). Intermediate transit nodes (**Zero-Knowledge Relays**) cannot decrypt, inspect, or modify user payload data.
> * **Signed Releases:** All official binary artifacts are digitally signed with an **Ed25519** private key and Sigstore/Cosign. The built-in auto-updater strictly verifies cryptographic signatures and rejects unverified binaries.
> * **WebUI Hardening:** WebUI binds strictly to `127.0.0.1` by default (except Keenetic routers for local LAN administration), protected by session tokens, CSRF validation, and DNS Rebinding filters.

---

## 📚 Documentation & Knowledge Base

* 🚀 [**Quick Start in 5 minutes**](https://github.com/jamixm4-crypto/natbypass/wiki/Quick-Start) — connect your first P2P pair of devices without console commands.
* 🎮 [**Practical Use Cases**](docs/USE_CASES.md) — LAN gaming with 0 relay latency, accessing home NAS/Plex without a static public IP, private Exit Node setup.
* 📶 [**Cellular Operators & DPI Presets**](docs/OPERATOR_PRESETS.md) — tested AmneziaWG and port configurations for MTS, MegaFon, Beeline, Tele2, Yota.
* 🛡️ [**Censorship Bypass (AmneziaWG)**](https://github.com/jamixm4-crypto/natbypass/wiki/AmneziaWG-DPI-Bypass) — tuning Jc, Jmin, Jmax, S1, S2, H1..H4 parameters against deep packet inspection (DPI / TSPU).
* 🔐 [**Security Threat Model**](docs/THREAT_MODEL.md) — formal threat boundaries, security guarantees, adversary capabilities, and relay safety.
* 🌐 [**Keenetic Routers (Entware)**](https://github.com/jamixm4-crypto/natbypass/wiki/Keenetic-Routers) & [**OpenWrt**](https://github.com/jamixm4-crypto/natbypass/wiki/OpenWrt-Routers) — 1-command installation and daemon service setup.
* 📱 [**Android Guide**](https://github.com/jamixm4-crypto/natbypass/wiki/Android-Setup) — connect via QR code, interactive on-screen QR display, and native VpnService.
* 🪟 [**Windows Guide**](https://github.com/jamixm4-crypto/natbypass/wiki/Windows-Guide) — native GUI, system tray, Wintun driver, and server background mode.
* 🧪 [**Updating & Beta Channel**](https://github.com/jamixm4-crypto/natbypass/wiki/Updating-and-Beta-Versions) — 1-click upgrade instructions for Windows, Linux, routers, and Android.
* 🔧 [**Diagnostics and Troubleshooting**](https://github.com/jamixm4-crypto/natbypass/wiki/Troubleshooting-and-Diagnostics) — universal diagnostic scripts and end-to-end ICMP ping verification.
* 🌍 [**natbypass-probe: Cross-border Diagnostics**](docs/PROBE.md) — automated probe utility detecting UDP drops and DPI filtering across geographical regions (BY, RU, US).
* ⚡ [**Multi-Tier NAT Traversal**](docs/NAT_TRAVERSAL.md) — 5-tier CGNAT bypass, ⚡ Coordinator and 🛡️ Relay badge guide.
* 📜 [**Third-Party Licenses**](THIRD_PARTY_LICENSES.md) — dependency licensing audit (WireGuard, Wintun, NaCl, Pion STUN).

---

## ✨ Key Features

- ⚡ **Pure P2P UDP Mesh:** Direct datagram communication between peers via STUN UDP Hole Punching without renting VPS servers.
- 🛡️ **AmneziaWG Obfuscation:** Built-in Deep Packet Inspection (DPI) protection with custom obfuscated headers (H1..H4), junk packets (Jc, Jmin, Jmax), header protection, and content padding randomization (S1, S2).
- 🔄 **Self-Healing Relay Failover:** When direct P2P is obstructed (double Symmetric NAT), traffic automatically reroutes through an elected intermediate mesh relay (Zero-Knowledge Multi-Hop), and seamlessly returns to 100% direct wire-speed P2P when direct connectivity recovers.
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
Run diagnostic script as Administrator:
```powershell
irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex
```
*(or via CLI: `.\natbypass-cli.exe diag`)*

### 🌍 Cross-Border P2P/DPI Diagnostics (natbypass-probe)
Standalone utility to diagnose UDP filtering, WireGuard signature drops, and AmneziaWG effectiveness across countries:

**Linux:**
```bash
curl -sSL -o natbypass-probe https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-probe-linux-amd64 && chmod +x natbypass-probe
./natbypass-probe --config probe.json --label "US / VPS" --country US --out report-us.json
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri "https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-Probe.exe" -OutFile "natbypass-probe.exe"
.\natbypass-probe.exe --config probe.json --label "RU / Home" --country RU --out report-ru.json
```
Full documentation: [**docs/PROBE.md**](docs/PROBE.md).

---

## 🏗️ P2P Mesh Architecture

```
              ┌──────────────────────────────────────────────────────────┐
              │             Signaling Channels (E2EE)                    │
              │  [Telegram Bot] ── [MQTT Broker] ── [Cloudflare DNS/Web] │
              └────────▲────────────────────────────────────────▲────────┘
                       │          (encrypted beacons)           │
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

## ⚡ Multi-Tier NAT Traversal

NatBypass implements an autonomous **5-tier NAT Traversal pipeline** allowing mobile nodes behind symmetric CGNAT (MTS, MegaFon, Beeline, Tele2, Yota) to establish direct connections or route via relays **without rented external VPS servers**:

| Tier | Technology | Description |
|---|---|---|
| **Tier 1** | **IPv6 Dual-Stack P2P** | Parallel AAAA STUN discovery and direct P2P hole pinholing via IPv6, bypassing operator IPv4 CGNAT entirely. |
| **Tier 2** | **DPI Drop Detection** | When 10 unacknowledged probes occur (TSPU filter), auto-activates `awg31_strict` with obfuscated headers for 10 minutes. |
| **Tier 3** | **Leader-Coordinated Punch** | Millisecond-precision simultaneous packet burst coordinated by an open/Cone NAT node. |
| **Tier 4** | **ASN-Aware Port Prediction** | Selective port delta prediction (+2, +4) based on carrier behavior database; random sweeps suppressed to protect battery. |
| **Tier 5** | **Peer-as-Relay** | Autonomous Zero-Knowledge MultiHop transit via trusted home routers (Keenetic, OpenWrt, PC) within daily quotas. |

### 🎯 Badges in WebUI & Android:
- ⚡ **Coordinator** (`coordinator_capable`) — Node with Full-Cone NAT or public IP that assists two CGNAT peers in simultaneous hole-punching.
- 🛡️ **Relay** (`relay_capable`) — Node (Keenetic router, Linux server, or desktop PC) with `enable_relay_server: true` providing transparent fallback transit. *(Android nodes on mobile data or low battery are automatically excluded).*
- 🌐 **Exit Node** (`is_exit_node`) — Node configured as a secure Internet Gateway.
- 🏠 **Subnet Route** (`advertised_routes`) — Node advertising LAN access (e.g. `192.168.1.0/24`).

👉 Full specification: [**docs/NAT_TRAVERSAL.md**](docs/NAT_TRAVERSAL.md).

---

## 📦 Supported Platforms

| Platform | Architecture | Release Binary | Description |
|---|---|---|---|
| **Windows (WebUI)** | amd64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11** (Browser dashboard at `http://localhost:8080` + system tray + Wintun) |
| **Windows (GUI)** | amd64 | [NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11** & **Windows Server (2016–2025)** (Pure native Win32 GUI, 15MB RAM + tray) |
| **Windows (CLI)** | amd64 | [natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest) | **Windows 10 / 11 / Server** (Console version for scripts and services) |
| **Android** | arm64 / arm / x64 | [NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 8.0+ (Native VpnService + QR Scanner + On-screen QR) |
| **Linux** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Ubuntu, Debian, CentOS, Arch |
| **Linux ARM64** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Raspberry Pi 3/4/5, Keenetic Ultra/Giga |
| **Routers MIPS** | mips (Big Endian) | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest) | OpenWrt (TP-Link, GL.iNet, Atheros) |
| **Routers MIPSLE** | mipsle (Little Endian)| [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest)| Keenetic Start/City/Air, Xiaomi 3G/4A |

---

## 🚀 Quick Installation

### Windows
* **Windows 10 / 11 (WebUI edition):**
  1. Download [**NatBypass.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
  2. Run as Administrator to configure the Wintun adapter. Open `http://localhost:8080` in your browser.
* **Windows 10 / 11 & Windows Server (Native GUI edition):**
  1. Download [**NatBypass-GUI.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest).
  2. Run as Administrator. A lightweight native Win32 window will open (no browser or Electron needed, 15–25MB RAM).
* **Windows Server / Headless (CLI):**
  1. Download [**natbypass-cli.exe**](https://github.com/jamixm4-crypto/natbypass/releases/latest). Run: `.\natbypass-cli.exe -c config.yaml`.

### Linux / Keenetic / OpenWrt (1-Command Install)
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
*(or via wget: `wget -qO- https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh`)*

WebUI will be available at: `http://<DEVICE_IP>:8080`.

---

## 🗑️ Uninstallation & Configuration Reset (Linux / Keenetic / OpenWrt)

### 1. Complete Uninstallation (Purge all files, services & keys):
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

### 2. Reset Configuration Only (Keep service and binaries):
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

---

## 🛡️ AmneziaWG (DPI Obfuscation)

NatBypass includes **AmneziaWG** protocol obfuscation engineered against deep packet inspection:

| Preset | Description | Target Use Case |
|---|---|---|
| **`Strict`** | Header Protection + Random Trailers + Disable Cookies + Content Padding + CPS Packets + Random Timers | **Maximum DPI / TSPU Censorship Bypass** |
| **`Balanced`** | Header Protection + Random Trailers + Cookies + Content Padding + Standard Jitter | Default recommended for all networks |
| **`Anti-TSPU`** | Custom parameter tuning (Jc=5, S2=100, randomized H1..H4) | Cellular networks (MTS, MegaFon, Tele2) |
| **`Legacy`** | Standard WireGuard + junk packets (Jc=4, S1=48, S2=32) | Legacy clients |

Full carrier presets matrix: [**docs/OPERATOR_PRESETS.md**](docs/OPERATOR_PRESETS.md).

---

## ⚖️ Legal & Regulatory Compliance

NatBypass is created for personal privacy, security research, and connecting authorized personal devices. Users are solely responsible for ensuring compliance with all local laws and regulations governing cryptography and virtual private networks in their jurisdiction.

---

## 📄 License

This project is licensed under the open-source [GNU General Public License v3.0 (GPLv3)](LICENSE). Third-party library licenses are detailed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
