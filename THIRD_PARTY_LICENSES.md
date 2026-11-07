# Third-Party Software & Licenses

NatBypass is licensed under the **GNU General Public License v3.0 (GPLv3)**.
This document lists the open-source third-party dependencies, libraries, and components utilized by NatBypass, along with their respective licensing terms.

---

## 1. Core VPN & Networking Components

### AmneziaWG / WireGuard Engine
- **Components**: AmneziaWG Protocol Obfuscation & WireGuard implementation
- **Upstream Projects**: [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go), [WireGuard-Go](https://git.zx2c4.com/wireguard-go)
- **License**: [GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) / [MIT](https://opensource.org/licenses/MIT)
- **Copyright**: © Jason A. Donenfeld, © Amnezia VPN Authors
- **Compliance Notice**: NatBypass is distributed under GPLv3, which is fully compatible with GPLv2-or-later components.

### Wintun Driver (Windows TUN Adapter)
- **Component**: `wintun.dll` (Windows TUN Network Adapter)
- **Upstream Project**: [Wintun](https://www.wintun.net/)
- **License**: [MIT](https://opensource.org/licenses/MIT)
- **Copyright**: © 2018-2021 WireGuard LLC. All rights reserved.
- **Redistribution Terms**:
  > Permission is hereby granted, free of charge, to any person obtaining a copy
  > of this software and associated documentation files (the "Software"), to deal
  > in the Software without restriction, including without limitation the rights
  > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  > copies of the Software, and to permit persons to whom the Software is
  > furnished to do so, subject to the following conditions:
  > The above copyright notice and this permission notice shall be included in all
  > copies or substantial portions of the Software.

---

## 2. Cryptographic & Protocol Libraries

### Go Cryptography Extensions (`golang.org/x/crypto`)
- **Package**: `golang.org/x/crypto` (NaCl SecretBox, Curve25519, ChaCha20-Poly1305, Ed25519, BLAKE2s, HKDF)
- **License**: [BSD 3-Clause](https://opensource.org/licenses/BSD-3-Clause)
- **Copyright**: © 2009 The Go Authors. All rights reserved.

### Pion STUN / NAT Traversal
- **Package**: `github.com/pion/stun/v3`
- **License**: [MIT](https://opensource.org/licenses/MIT)
- **Copyright**: © 2018-2026 Pion Community

### Eclipse Paho MQTT Golang Client
- **Package**: `github.com/eclipse/paho.mqtt.golang`
- **License**: [Eclipse Public License 2.0 (EPL-2.0)](https://www.eclipse.org/legal/epl-2.0/) and [Eclipse Distribution License 1.0 (EDL-1.0)](https://www.eclipse.org/org/documents/edl-v10.php)
- **Copyright**: © 2013-2026 Eclipse Foundation

### Gorilla WebSocket
- **Package**: `github.com/gorilla/websocket`
- **License**: [BSD 2-Clause](https://opensource.org/licenses/BSD-2-Clause)
- **Copyright**: © 2013 The Gorilla WebSocket Authors. All rights reserved.

---

## 3. System & Utilities

### Windows System Integration (`golang.org/x/sys/windows`)
- **Package**: `golang.org/x/sys`
- **License**: [BSD 3-Clause](https://opensource.org/licenses/BSD-3-Clause)
- **Copyright**: © 2009 The Go Authors. All rights reserved.

### Cobra & Viper (CLI & Config)
- **Packages**: `github.com/spf13/cobra`, `github.com/spf13/viper`
- **License**: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- **Copyright**: © 2013-2026 Steve Francia

### Zerolog (Fast Logging)
- **Package**: `github.com/rs/zerolog`
- **License**: [MIT](https://opensource.org/licenses/MIT)
- **Copyright**: © 2017 Olivier Poitrey

### QR Code Generator
- **Package**: `github.com/skip2/go-qrcode`
- **License**: [MIT](https://opensource.org/licenses/MIT)
- **Copyright**: © 2014-2020 Tom Harwood

---

## 4. License Summary Table

| Library / Component | Primary Function | Upstream License | Distribution Compatibility |
| :--- | :--- | :--- | :--- |
| **AmneziaWG / WireGuard** | Tunneling & Obfuscation | GPLv2 / MIT | Compatible with GPLv3 |
| **Wintun DLL** | Windows L3 TUN driver | MIT | Included dynamically / downloaded on install |
| **golang.org/x/crypto** | E2EE NaCl Box / Poly1305 | BSD 3-Clause | Compatible with GPLv3 |
| **pion/stun/v3** | RFC 5389 / 5780 NAT audit | MIT | Compatible with GPLv3 |
| **paho.mqtt.golang** | Distributed signaling | EDL-1.0 / EPL-2.0 | Compatible with GPLv3 |
| **gorilla/websocket** | Signaling & Tunnel fallback | BSD 2-Clause | Compatible with GPLv3 |
| **zerolog** | High-performance logger | MIT | Compatible with GPLv3 |
| **spf13/cobra** | Command Line Interface | Apache 2.0 | Compatible with GPLv3 |
