# NatBypass

**High-performance decentralized P2P Mesh VPN with AmneziaWG obfuscation, Zero CGO, and carrier-grade NAT traversal for Keenetic, OpenWrt, Windows, Linux, and Android.**

[🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/jamixm4-crypto/natbypass?style=flat&logo=github&color=8b5cf6)](https://github.com/jamixm4-crypto/natbypass/releases/latest)
[![Wiki](https://img.shields.io/badge/Wiki-Documentation-blue?style=flat&logo=gitbook)](https://github.com/jamixm4-crypto/natbypass/wiki)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Zero CGO](https://img.shields.io/badge/CGO-Zero%20(Pure%20Go)-blue)](https://golang.org)

---

> [!NOTE]
> ### 🛡️ Project Purpose & Security Disclaimer
> **NatBypass** is an open-source decentralized P2P Mesh VPN designed solely for personal privacy, inter-connecting personal and home devices (Keenetic/OpenWrt routers, home PCs, smartphones, NAS) into a secure mesh network, and bypassing DPI censorship.
> * **Not a Pentesting Tool:** NatBypass is **NOT** a penetration testing tool, port scanner, backdoor, or remote access Trojan (RAT). It has **NO affiliation or relation** to legacy tunneling utilities (such as `cw1997/NATBypass` or `lcx`).
> * **End-to-End Encryption (E2EE):** All user traffic is encrypted using Noise_IK / ChaCha20-Poly1305. Intermediate transit nodes (**Zero-Knowledge Relays**) cannot decrypt or inspect user payload.
> * **Cryptographically Signed Releases:** Official binaries are digitally signed with an **Ed25519** key and Cosign. The built-in updater strictly verifies signatures and rejects unverified binaries.

---

## ✨ Key Features

* ⚡ **Pure P2P UDP Mesh:** Direct socket-to-socket datagram exchange via STUN Hole Punching without rented external VPS servers.
* 🛡️ **AmneziaWG 3.1 & DPI Bypass:** Resistance against deep packet inspection (DPI / TSPU) with junk packets (`Jc`), custom headers (`H1`–`H4`), and dynamic padding (`S1`, `S2`).
* 🔄 **Self-Healing Relay Failover:** When direct connectivity is obstructed (double Symmetric NAT), traffic automatically routes through a trusted relay peer, returning to 100% direct P2P when direct paths open.
* 🌐 **Internet Exit Node Gateway:** Route all internet traffic through your home router with 1-click control and full DNS leak protection.
* 🚀 **Embedded Router Optimizations:** Zero CGO pure Go runtime with RAM consumption bounded to 48MB — running stably even on 64–128MB RAM MIPS/ARM routers (Keenetic, OpenWrt).
* 🪟 **Native Win32 GUI:** Ultra-lightweight native interface without Electron or browser bloat (15–25MB RAM) for Windows 10/11 and Server.
* 📱 **Android 10–15 All-in-One:** Native asynchronous VpnService with on-screen interactive QR sharing.

---

## 🏗️ Architecture

```
         ┌──────────────────────────────────────────────────────────┐
         │             Signaling Channels (E2EE)                    │
         │  [Telegram Bot] ── [MQTT Broker] ── [Cloudflare DNS/Web] │
         └────────▲────────────────────────────────────────▲────────┘
                  │          (encrypted beacons)            │
                  │                                         │
    ┌─────────────┴──────────┐                   ┌──────────┴─────────────┐
    │    Device A            │                   │    Device B            │
    │  STUN Discovery        │                   │  STUN Discovery        │
    │  Windows (Wintun)      │                   │  Keenetic / Android    │
    │  VIP: 100.64.200.1     │                   │  VIP: 100.64.200.2     │
    └─────────────┬──────────┘                   └──────────┬─────────────┘
                  │                                         │
                  └─────────── Direct UDP Socket ───────────┘
                            (P2P Mesh / AmneziaWG)
```

---

## 🚀 1-Minute Quick Start

### 🐧 Keenetic, OpenWrt Routers & Linux Servers
Install daemon and system service in one command:
```bash
curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/install.sh | sh
```
Web Management UI will be accessible at: `http://<DEVICE_IP>:8080`.

### 🪟 Windows (Desktop & Server)
* **[NatBypass-GUI.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest)** — native Win32 lightweight UI (system tray, Wintun).
* **[NatBypass.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest)** — background service with WebUI at `http://localhost:8080`.
* **[natbypass-cli.exe](https://github.com/jamixm4-crypto/natbypass/releases/latest)** — console utility for automation.

### 📱 Android
* Download **[NatBypass.apk](https://github.com/jamixm4-crypto/natbypass/releases/latest)** to connect your phone via QR code.

---

## 🔍 Express Diagnostics

Verify network connectivity, STUN status, and peer reachability in one command:
* **Linux / Routers:** `curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.sh | sh`
* **Windows (PowerShell):** `irm https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/scripts/diag.ps1 | iex`
* **In WebUI:** click **"⚡ 1-Click Diagnostics"** on the Diagnostics tab.

---

## 📚 Documentation & Knowledge Base

Detailed technical documentation is available in the Wiki and `docs/`:

* 🚀 [**Quick Start in 5 Minutes**](wiki/Quick-Start.md) — step-by-step device onboarding.
* 🎮 [**Practical Use Cases**](docs/USE_CASES.md) — LAN gaming with 0 latency, accessing home NAS, private Exit Node.
* 📶 [**Carrier Presets (MTS, MegaFon, Beeline, Tele2, Yota)**](docs/OPERATOR_PRESETS.md) — DPI bypass configurations.
* 🌐 [**Keenetic Routers**](wiki/Keenetic-Routers.md) & [**OpenWrt**](wiki/OpenWrt-Routers.md) — router installation and fine-tuning.
* 🛡️ [**Internet Exit Node Guide**](wiki/Exit-Node-Guide.md) — gateway and DNS leak protection.
* ⚡ [**Multi-Tier NAT Traversal**](wiki/NAT-Traversal-Explained.md) — penetrating Symmetric NAT and peer coordination.
* 🔐 [**Security Threat Model**](docs/THREAT_MODEL.md) — formal security boundaries and audit.
* 🗑️ [**Uninstallation & Configuration Reset**](wiki/Uninstallation-and-Reset.md) — purging and resetting configuration.

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
