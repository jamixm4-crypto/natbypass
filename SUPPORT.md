# Support Guide

Thank you for using NatBypass! Before seeking help, please review this guide to find the quickest path to a solution.

---

## 📚 1. Knowledge Base & Documentation First

Most setup questions, router configurations, and AmneziaWG tuning options are already covered in detail:

- 📖 [**Official NatBypass Wiki**](wiki/Home.md)
- 🚀 [**Quick Start Guide**](wiki/Quick-Start.md)
- 🌐 [**Keenetic Routers**](wiki/Keenetic-Routers.md) & [**OpenWrt**](wiki/OpenWrt-Routers.md)
- 🎮 [**Practical Use Cases (LAN gaming, NAS, Exit Node)**](docs/USE_CASES.md)
- 📶 [**Carrier Presets (MTS, MegaFon, Beeline, Tele2, Yota)**](docs/OPERATOR_PRESETS.md)
- 🔧 [**Troubleshooting & Diagnostics**](wiki/Troubleshooting-and-Diagnostics.md)

---

## 💬 2. General Questions & Community Discussion

For general questions, configuration sharing, and community discussions:

- **GitHub Discussions**: Use the [Discussions tab](https://github.com/jamixm4-crypto/natbypass/discussions) to ask questions, share router configurations, and request advice.
- Please do not open GitHub Issues for general "how do I configure..." questions if they are already answered in the Wiki.

---

## 🐛 3. Bug Reports & Crashes

If you encountered a bug, panic, or unexpected behavior in the daemon or GUI:

1. Run the built-in diagnostic utility:
   ```bash
   # Linux / Keenetic / OpenWrt
   natbypass diag
   ```
   ```powershell
   # Windows PowerShell
   .\natbypass-cli.exe diag
   ```
2. Open a new issue using our [Bug Report Template](https://github.com/jamixm4-crypto/natbypass/issues/new?template=bug_report.yml).
3. Include:
   - NatBypass version (e.g. `v1.9.505-beta.1`).
   - OS & architecture (Keenetic MIPSle, OpenWrt ARM, Windows 11 x64, Android 14).
   - Sanitized diagnostic report.

---

## 🔒 4. Security Vulnerabilities

If you discovered a potential security vulnerability, **do NOT** open a public issue.
Please follow the instructions in [**SECURITY.md**](SECURITY.md) to report it confidentially via GitHub Private Vulnerability Reporting.
