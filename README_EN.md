# NatBypass

**P2P Mesh VPN & DPI Bypass** — direct socket-to-socket connections between computers, servers, phones, and routers across all types of NAT/CGNAT without dedicated servers.

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Keenetic%20%7C%20OpenWrt%20%7C%20Android-brightgreen)](#-supported-platforms)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

> [!NOTE]
> **NatBypass** is an open-source decentralized P2P Mesh VPN designed to securely connect personal devices (Keenetic/OpenWrt routers, Android phones, home PCs, NAS, and servers) into a private encrypted overlay mesh without public IPv4 addresses and bypass DPI censorship. All user traffic is protected by end-to-end encryption (Noise_IK / ChaCha20-Poly1305), intermediate transit nodes (**Zero-Knowledge Relays**) cannot decrypt or inspect payload data, and official release binaries are cryptographically signed with an **Ed25519** key.

---

## ✨ Key Features

* ⚡ **Pure P2P UDP Mesh:** Direct socket-to-socket datagram exchange via STUN UDP Hole Punching without external relay VPS servers or public IPs.
* 🛡️ **AmneziaWG & DPI Bypass:** Resistance against deep packet inspection (DPI / TSPU) with junk packets (`Jc`), custom magic headers (`H1`–`H4`), and dynamic padding (`S1`, `S2`).
* 🔄 **Self-Healing Relay Failover:** When direct P2P is blocked (e.g. double Symmetric NAT), traffic automatically routes through a trusted relay peer, seamlessly returning to direct P2P once paths open.
* 🌐 **Internet Exit Node Gateway:** Route all internet traffic through your home router with 1-click control, full DNS leak protection, and anti-routing-loop safeguards.
* 🚀 **Embedded Router Optimizations:** Zero CGO pure Go runtime with RAM consumption bounded to 48MB — running stably even on 64–128MB RAM MIPS/ARM routers (Keenetic, OpenWrt).
* 🪟 **Native Win32 GUI:** Ultra-lightweight native desktop interface without Electron or browser bloat (15–25MB RAM) for Windows 10/11 and Windows Server.
* 📱 **Android 10–15 All-in-One:** System asynchronous `VpnService` with 1-click QR code pairing and quick settings tile.

---

## 🏗️ Architecture

```
         ┌──────────────────────────────────────────────────────────┐
         │             Signaling Channels (E2EE)                    │
         │  [MQTT Mesh Brokers] ── [LAN UDP Discovery] ── [Telegram]│
         └────────▲────────────────────────────────────────▲────────┘
                  │          (encrypted beacons)            │
                  │                                         │
    ┌─────────────┴──────────┐                   ┌──────────┴─────────────┐
    │     Node A (PC)        │                   │   Node B (Keenetic)    │
    │  STUN: 37.212.11.11    │                   │  STUN: 37.212.34.205   │
    │  VIP: 10.1.2.171       │                   │  VIP: 10.1.2.217       │
    └─────────────┬──────────┘                   └──────────┬─────────────┘
                  │                                         │
                  └─────────── Direct UDP Socket ───────────┘
                         (P2P Mesh / AmneziaWG)
```

---

## 📦 Supported Platforms

| Platform | Architecture | Binary Asset | Description |
|---|---|---|---|
| **Windows (GUI & WebUI)** | x86_64 | [NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass.exe) | Full-featured app in dedicated window (no browser tabs, WebView2 / App Window, tray) |
| **Windows (Native Win32)** | x86_64 | [NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-GUI.exe) | Ultra-lightweight native Win32 app (GDI/User32, no browser runtime, 15–25 MB RAM) |
| **Windows (CLI / Service)** | x86_64 | [natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-cli.exe) | Command-line utility for scripts, automation, and Windows service |
| **Linux (x86_64)** | amd64 | [natbypass-linux-amd64](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-amd64) | Ubuntu, Debian, CentOS, Fedora, Arch servers |
| **Linux (ARM64)** | arm64 | [natbypass-linux-arm64](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-linux-arm64) | Raspberry Pi 3/4/5, ARM servers, Orange Pi |
| **Keenetic (MIPSLE)** | mipsle | [natbypass-keenetic-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-keenetic-mipsle) | Keenetic Titan, Hero, Hopper, Speedster, City, Air |
| **OpenWrt (MIPS)** | mips | [natbypass-router-mips](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-router-mips) | OpenWrt on Atheros / Qualcomm CPUs (Big Endian) |
| **OpenWrt (MIPSLE)** | mipsle | [natbypass-router-mipsle](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-router-mipsle) | OpenWrt on MediaTek / Ralink CPUs (Little Endian) |
| **Android** | arm64 / universal | [Download APK](https://github.com/jamixm4-crypto/natbypass/releases/latest) | Android 10–15: VpnService, Quick Settings Tile, QR scanner |

---

## 🚀 1-Minute Quick Start

### 🐧 Keenetic, OpenWrt Routers & Linux Servers
Install daemon, system service, and enable autostart in one command:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
Web Management UI will be accessible at: `http://<DEVICE_IP>:8080`.

### 🪟 Windows
* **[NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass.exe)** — primary Windows application: runs directly **in its own dedicated window** (no browser address bar or tabs), features system tray, interactive topology map, and speed graphs.
* **[NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/NatBypass-GUI.exe)** — ultra-lightweight classic Win32 edition (pure Windows API, no browser engine, uses only 15–25 MB RAM).
* **[natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest/download/natbypass-cli.exe)** — console utility for automation, scripts, and installing Windows background service.

### 📱 Android
1. **App Installation:**
   * Scan the **APK download QR code** (select `📱 Download APK` in the QR modal on your PC) using standard phone camera;
   * Or download the APK manually from the [latest release page](https://github.com/jamixm4-crypto/natbypass/releases/latest).
2. **Instant Mesh Onboarding:**
   * Open the installed **NatBypass Android** app.
   * Tap **"📷 Scan QR"** and point camera at the network profile QR code (`🔒 Profile`) on your PC or router screen — connection activates instantly with all keys and parameters!

---

## 🔄 How to Update to the Beta Version (All Platforms)

All cutting-edge fixes, new NAT traversal algorithms, and P2P/AWG improvements are published first on the **Beta (Pre-release)** track.

### 🐧 Keenetic, OpenWrt Routers & Linux Servers
* **Update existing daemon to the latest Beta in one command:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/update.sh | sh -s -- --beta
  ```
* **Install Beta directly from scratch:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh -s -- --beta
  ```
* **Via WebUI:** Open router WebUI (`http://<ROUTER_IP>:8080`) → **System / Updates**, switch to the **Beta Channel**, and click **"Check and Update"**.

### 🪟 Windows (PC & Servers)
* **Method 1 (Directly within running app):**
  In the app window, click **"⚙️ Updates"** (or visit WebUI `http://127.0.0.1:8080` → **System / Updates**), select the **Beta** channel, and click **"Update Now"** — the app will download and restart seamlessly without losing your configuration.
* **Method 2 (PowerShell one-liner):**
  ```powershell
  irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/install-windows.ps1 | iex -ArgumentList "-Beta"
  ```
* **Method 3 (Manual Download from GitHub Releases):**
  Download the latest binaries from the active [**Pre-release (v1.9.507-beta.12)**](https://github.com/jamixm4-crypto/natbypass/releases/tag/v1.9.507-beta.12) page:
  * **[NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.507-beta.12/NatBypass.exe)** — primary standalone application (App Window / WebUI, system tray, interactive topology map).
  * **[NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.507-beta.12/NatBypass-GUI.exe)** — ultra-lightweight native Win32 GUI (15–25 MB RAM).
  * **[natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/download/v1.9.507-beta.12/natbypass-cli.exe)** — console client and Windows background service.

### 📱 Android
1. Open the [**Pre-release (v1.9.507-beta.12)**](https://github.com/jamixm4-crypto/natbypass/releases/tag/v1.9.507-beta.12) page on your phone and download the `NatBypass.apk`.
2. Or in the desktop app, open the "📱 Download APK" tab in the QR modal and scan with your phone camera.

---

## 🗑️ Uninstallation & Configuration Reset (Linux / Keenetic / OpenWrt)

### 1. Complete Uninstallation (Purge all binaries, configs, and keys):
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --purge
```

### 2. Clean & Reset Configuration (Keep binary, regenerate DeviceID and keys):
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/uninstall.sh | sh -s -- --reset-config
```

---

## 🛡️ AmneziaWG (DPI & Censorship Resistance)

NatBypass includes built-in support for **AmneziaWG** — a WireGuard modification featuring behavioral obfuscation against deep packet inspection.

| Preset | Parameters | Best Suited For |
|---|---|---|
| **`Anti-TSPU`** | `Jc=4-5`, `S1=56`, `S2=80-100`, randomized `H1..H4` | **Mobile carrier networks (MTS, MegaFon, Tele2)** |
| **`Strict`** | Maximum padding, randomized rekey timers, random trailers | Aggressive corporate or state DPI filters |
| **`Balanced`** | Header protection + moderate padding + standard keepalive | Default optimal mesh operation |
| **`Light`** | Minimal padding (`Jc=2`, `S1=32`, `S2=48`) | Home fiber PON / Ethernet networks |

Full operator presets table: [**docs/OPERATOR_PRESETS.md**](docs/OPERATOR_PRESETS.md).

---

## 🔍 Express Diagnostics

* **Linux / Routers:** `curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh`
* **Windows (PowerShell):** `irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex`
* **In WebUI:** click **"⚡ 1-Click Diagnostics"** on the Diagnostics tab.
* **Cross-Network Tester:** [NatBypass-Probe](wiki/Probe-Diagnostics.md) for RFC 5780 NAT classification and DPI probing.

---

## 📚 Documentation & Knowledge Base

* 🚀 [**Quick Start in 5 Minutes**](wiki/Quick-Start.md) — step-by-step device onboarding.
* 🎮 [**Practical Use Cases**](docs/USE_CASES.md) — LAN gaming with 0 latency, accessing home NAS, private Exit Node.
* 📶 [**Carrier Presets**](docs/OPERATOR_PRESETS.md) — DPI bypass settings for MTS, MegaFon, Beeline, Tele2, Yota.
* 🌐 [**Keenetic Routers**](wiki/Keenetic-Routers.md) & [**OpenWrt**](wiki/OpenWrt-Routers.md) — router installation and fine-tuning.
* 🛡️ [**Internet Exit Node Guide**](wiki/Exit-Node-Guide.md) — gateway and DNS leak protection.
* ⚡ [**Multi-Tier NAT Traversal**](wiki/NAT-Traversal-Explained.md) — penetrating Symmetric NAT and peer coordination.
* 🔐 [**Security Threat Model**](docs/THREAT_MODEL.md) — formal security boundaries and audit.
* 🗑️ [**Uninstallation & Reset**](wiki/Uninstallation-and-Reset.md) — purging and resetting configuration.

---

## 🤝 Community Standards

* 📋 [**Contributing Guidelines**](CONTRIBUTING.md)
* 🤝 [**Code of Conduct**](CODE_OF_CONDUCT.md)
* 🔒 [**Security Policy**](SECURITY.md)
* 💬 [**Support Guide**](SUPPORT.md)
* 📜 [**Third-Party Licenses**](THIRD_PARTY_LICENSES.md)

---

## 📄 License

This project is licensed under the open-source [GNU General Public License v3.0 (GPLv3)](LICENSE).
